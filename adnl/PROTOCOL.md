# tos-adnl-probe protocol — `tos-adnl-probe/1`

`tos-adnl-probe` is a standalone measurement sidecar around the native C++
ADNL stack. A collector process drives it over a line-delimited JSON protocol
on stdin/stdout to run reachability experiments (dial, hold, reconnect, echo)
against another probe instance or any other ADNL implementation that follows
the same conventions. Only protocol JSON is written to stdout (one object per
line, flushed); all logging goes to stderr.

## Startup

On start the sidecar emits exactly one `hello` event:

```json
{"event":"hello","protocol":"tos-adnl-probe/1","implementation":"tos-native-adnl","implementation_commit":"<40-hex git commit of the tree>","toolchain":"<compiler id/version>","target":"<os/arch>"}
```

## Command / completion model

Commands arrive one JSON object per line on stdin. Every command carries an
integer `id` and a string `cmd`. Every command is answered by exactly one
completion event carrying the same `id`.

- Errors: `{"id":N,"event":"error","message":"..."}`.
- A malformed line is answered with an `id` of `0`.
- An unknown `cmd` is answered with an error; the process keeps running.
- The process exits cleanly (status 0) on the `close` command or on stdin EOF.

**Session-operation serialization (lease):** at most one of
{`dial`, `await`, `hold`, `reconnect`, `echo`} is active at a time. A
session command arriving while another one is in flight completes
immediately with an error event naming the busy operation (e.g.
`"busy: hold in progress"`) — fail-closed, never queued silently. This
guarantees one operation's channel reset or peer replacement can never be
recorded as another operation's network behavior. `identity`, `listen`,
`punch`, and `close` are outside the lease (`punch` still refuses a second
concurrent `punch`).

## Commands

### identity

```json
{"id":1,"cmd":"identity"}
→ {"id":1,"event":"identity","adnl_pubkey_hex":"<ed25519 public key hex>","adnl_id_hex":"<short id hex>"}
```

Generates (or returns the already-generated) ephemeral transport keypair
**without binding any socket**. A subsequent `listen` reuses exactly this
keypair. Calling `identity` first is optional — a bare `listen` generates
the keypair itself, exactly as before.

Rationale: an orchestrator can perform its coordinator rendezvous on its own
UDP socket first — the remote peer needs this probe's transport pubkey during
pairing — then close that socket and tell the sidecar to `listen` on the
**same** port, so the NAT mapping the coordinator observed is the mapping
the ADNL session runs over.

### listen

```json
{"id":1,"cmd":"listen","bind":"0.0.0.0:0"}
→ {"id":1,"event":"listening","addr":"<ip:port actually bound>","adnl_pubkey_hex":"<ed25519 public key hex>","adnl_id_hex":"<short id hex>"}
```

Creates a fresh ephemeral ed25519 transport key for this process (never a
persisted identity) — or reuses the keypair a prior `identity` command
generated — binds the UDP socket, and starts the ADNL stack (keyring,
network manager, local id) on it. Port `0` selects an ephemeral port; the
completion reports the port actually bound.

Implementation notes (native stack behavior, reported honestly):

- The native transport (`td::UdpServer::create`) always binds `0.0.0.0`; the
  IP part of `bind` selects the address family only. A non-IPv4 bind address
  is rejected with an error (see the IPv6 section below).
- Port 0 is resolved by pre-binding a discovery socket, reading the assigned
  port and rebinding it for the transport; a tiny race window exists between
  the two binds.
- An explicit port is probed with a bounded bind retry (20 × 50 ms) before
  the transport takes it, so the rendezvous handoff above works even when
  the caller's socket close is still settling; a bind that never succeeds is
  reported as a protocol `error` instead of aborting.
- The local id publishes a versioned address list with **zero addresses**:
  peers that support the implicit-address rule (the native stack does) reply
  to the observed UDP source address, which is the behavior a reachability
  probe wants both on loopback and behind NAT.

### punch

```json
{"id":2,"cmd":"punch","targets":["ip:port",...],"rounds":3,"interval_ms":100}
→ {"id":2,"event":"punched"}
```

Sends raw datagrams (64 random bytes) from the ADNL socket toward each target
to open NAT mappings. Content is arbitrary; receivers drop it (the native
receive path drops undecryptable packets silently). Targets dropped by the
implementation-limit filters (IPv6, port 0) are skipped with a stderr log;
the command still completes with `punched` for the remaining targets (punch
is best-effort by design, so no distinct completion exists here).

### dial

```json
{"id":3,"cmd":"dial","peer_pubkey_hex":"...","candidates":["ip:port",...],"timeout_ms":10000}
→ {"id":3,"event":"established","millis":<ms from command receipt to confirmed round trip>,"peer_addr":"ip:port"}
→ {"id":3,"event":"failed","class":"handshake-timeout"}
```

Registers the peer with the candidate addresses and confirms the session with
an ADNL-level query round trip (the echo query described below, 32-byte
payload), retried within the window. Failure classes: `no-candidate`,
`unsupported-candidate`, `handshake-timeout`, `udp-blocked`,
`peer-unreachable`, `internal-error`.

- `no-candidate`: the candidate list was empty (or contained nothing that
  parses as `ip:port` at all).
- `unsupported-candidate` (additive, this implementation): at least one
  candidate was supplied but **every** one was dropped by the sidecar's
  implementation-limit filters (IPv6, port 0 — see the send-abort notes
  below). This is an implementation limit, not network evidence: **no trial
  should ever be filed from it.** It exists precisely so implementation
  limits stay distinguishable from a genuinely empty usable candidate set.
- `handshake-timeout`: no round trip completed within `timeout_ms`.
- `udp-blocked` / `peer-unreachable`: accepted from other implementations
  but not produced here — the socket layer gives the native sidecar no way
  to distinguish them from a timeout.

### await

```json
{"id":4,"cmd":"await","peer_pubkey_hex":"...","timeout_ms":10000}
→ same completion events as dial
```

Responder side: never dials. Accepts the inbound session from the named peer
and confirms it with its own query round trip over that session (using the
implicit return address learned from the inbound packets).

### hold

```json
{"id":5,"cmd":"hold","window_ms":30000,"keepalive_ms":2000}
→ {"id":5,"event":"held","survival_seconds":N,"completed":true|false}
```

Runs keepalive round trips at the given interval until the window elapses
(`completed=true`, `survival` = full window) or 3 consecutive keepalives fail
(`completed=false`, `survival` = span from hold start to the last successful
round trip).

Completion rules:

- The hold is never reported `completed=true` while a keepalive round trip
  is still in flight: if the window elapses with one outstanding, the hold
  waits for that round trip (bounded by the keepalive's own timeout) and its
  result decides the verdict — a peer that died just before a short window
  is reported `completed=false`, not as having survived it. The same rule
  covers `keepalive_ms` larger than `window_ms`.
- With no keepalive outstanding at window expiry, `completed=true` requires
  the most recent round trip in the window to have succeeded.
- `survival_seconds` is whole seconds **by truncation with a minimum of 1**
  — the same clamped-seconds rule the collector applies, so identical trials
  produce identical evidence (zero already means "not measured" in the trial
  schema, so a measured hold always reports at least 1). E.g. a completed
  1500 ms window reports `survival_seconds:1`.

### reconnect

```json
{"id":6,"cmd":"reconnect","timeout_ms":10000}
→ {"id":6,"event":"reconnected","millis":N,"succeeded":true|false}
```

Deliberately drops the negotiated ADNL channel to the confirmed peer (the
local channel key is discarded and rotated, forcing a fresh
`createChannel`/`confirmChannel` exchange with a strictly newer key date) and
re-establishes with fresh round trips. Packet sequence state is preserved —
in the native stack the reinit date is fixed per process, so a full peer-state
reset inside one process would strand the session; dropping only the channel
matches what "channel loss" means on this wire protocol.

### echo

```json
{"id":7,"cmd":"echo","bytes":1024,"timeout_ms":10000}
→ {"id":7,"event":"echoed","ok":true|false,"sha256_hex":"<hex of the payload hash>","millis":N[,"error":"..."]}
```

Sends an ADNL custom query to the confirmed peer whose payload is the 16-byte
ASCII prefix `tosprobe-echo/1\n` followed by `bytes` random bytes. The answer
must be exactly the 32-byte sha256 of those random bytes. `ok` is true only
when the returned hash equals the locally computed one; `sha256_hex` is the
locally computed hash either way.

**Every** probe instance also answers such queries from its peer: a query
handler is registered at listen time; on the prefix it replies with the
sha256 of the remainder, anything else falls through untouched (other query
prefixes are rejected by the stack's normal no-subscriber path).

#### Native query-size cap (honest limitation)

The native stack caps ADNL query payloads at
`Adnl::huge_packet_max_size()` = **8192 bytes** (larger messages would be
refused by the peer table and the fragmentation path asserts at this bound).
Consequently:

- `echo` with `bytes` such that `16 + bytes > 8192` (so anything above
  8176 random bytes — including the required 65536 case) is **not sent**;
  the sidecar completes with `ok=false` and an `error` field naming the cap.
- `bytes:1024` works and exercises fragmentation (the ADNL message MTU is
  1024, so a 1040-byte payload is split into `adnl.message.part` fragments).
- Inbound behavior is symmetric: a ≥ 8 KiB query from another implementation
  is dropped by the native reassembly path (`huge message` limit), so the
  sender observes a timeout.

#### Native send-abort on invalid destinations (honest limitation)

The UDP server's send-error path is not survivable: a datagram whose
destination the kernel rejects (`sendmmsg` EINVAL) **aborts the process**.
Observed for two destination classes:

- IPv6 destinations through the IPv4-only socket (see the IPv6 section), and
- **port 0** destinations — e.g. a malformed peer advertising `ip:0`.

The sidecar therefore filters unusable endpoints out of `dial` candidates
and `punch` targets up front (IPv6 and zero/invalid ports, logged to
stderr); a `dial` whose supplied candidates were all dropped by these
filters completes with `failed` / `unsupported-candidate` (an
implementation-limit marker, never network evidence — see the dial
section). Note this protects only the addresses the
collector supplies: an address list *advertised by the remote peer inside
the ADNL session* is consumed by the library itself and is not filtered
here — the production pairing layer must not advertise `ip:0`.

### close

```json
{"id":8,"cmd":"close"} → {"id":8,"event":"closed"}
```

Then clean shutdown, exit 0.

`close` first **cancels any in-flight operation** with its own terminal
error completion — `{"id":<outstanding>,"event":"error","message":
"cancelled by close"}` — emitted **before** the `closed` event, so the
exactly-one-completion rule holds across shutdown (with the session lease,
at most one session operation plus one `punch` can be outstanding). Stdin
EOF also shuts down cleanly: in-flight operations are cancelled the same
way with `"cancelled by shutdown"`, and no `closed` event is emitted.

## IPv6 (measured on the native stack — do not infer from other implementations)

The owner's rule: native IPv6 support must be established from the native
code and tests, never inferred from tonutils-go behavior. Findings from this
tree, plus the loopback test in `test-adnl-probe.py`:

1. **Transport socket is IPv4-only.** `td::UdpServer::create` (the only
   socket the ADNL network manager opens) hard-codes
   `init_ipv4_port("0.0.0.0", port)`. There is no IPv6 or dual-stack
   listener. `listen` with a non-IPv4 bind address is therefore rejected
   with an explicit error rather than pretending to bind.
2. **Address publishing is IPv4-only.** The UDP address publishing path uses
   `get_ipv4()` / `adnl.address.udp`, and the implicit-source-address rule
   (`AdnlAddressList::add_udp_adnl_address`) returns an error for anything
   that is not IPv4.
3. **The TL schema and address list can carry IPv6** (`adnl.address.udp6`,
   `AdnlAddressUdp6` creates a connection actor), but the transport cannot
   deliver to it: when tested on `::1`, handing a udp6 candidate to the
   connection layer made the first send go through the IPv4 socket and
   **abort the process** inside the UDP server
   (`PollableFd.h: Check '!was_locked' failed`, SIGABRT) — the send-error
   path there is not survivable. The probe therefore filters non-IPv4
   candidates/targets up front instead of passing them into the stack:
   `dial` whose candidates are all IPv6 completes with
   `failed` / `unsupported-candidate`, and `punch` skips IPv6 targets
   (logged to stderr).

**Observed result on ::1 (2026-08-20, this tree):** `listen` on `::1:0`
fails with the explicit IPv4-only error; a raw `::1` dial candidate crashes
the native stack if forwarded (hence the filter), so `dial` with only `::1`
candidates completes with `failed` / `unsupported-candidate`. IPv6 is **not
functional** in the native ADNL transport; any cross-validation matrix must
treat native IPv6 cells as unsupported-by-implementation rather than as
network failures.

## Wire conventions relied on (for other implementations)

- Session confirmation, keepalives, and echo all use the same query payload
  format: `tosprobe-echo/1\n` + N random bytes → 32-byte sha256 answer.
  An implementation only needs to (a) answer such queries and (b) be able to
  send them, to interoperate with every command here.
- The dialer must include its (possibly empty) signed address list in the
  first packets so the responder can associate the full public key; the
  native stack does this automatically.
- The responder replies to the observed UDP source address when the dialer's
  address list contains no addresses (implicit address rule).
