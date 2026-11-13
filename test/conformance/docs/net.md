# net harness

The network wire layer: the bytes one node puts on the wire and what a receiving C++ node accepts,
refuses and extracts. `ref/harness-net.cpp` (dispatch, key operations, the refusal table) and
`ref/net-adnl.cpp`, `ref/net-overlay.cpp`, `ref/net-transport.cpp` call the node's own code; the
context field `op` selects one operation (`runner/harnesses/net.py`, `schema/harness/net-v1.schema.json`).

Byte strings are lowercase hex, 32-byte ids 64 lowercase hex digits, 64-bit values decimal strings.
Every effect is one outcome, or `{"outcome": "refused", "reason": <class>}` when node code refused the
input. The class comes from the fixed table `kReasonRules` over the node's messages, so two
implementations must agree on the class of a refusal, not on its wording; a message no rule matches is
`unclassified`, which shows up as a fixture diff the day a message changes. Verdicts inside an effect
(a packet's signature check, a channel's received datagram, a gate's per-event results, a decoder's
per-symbol results) use the same classes.

Inputs that are the local node's own configuration (its private keys, code parameters the node never
takes from a peer) and inputs outside the harness bounds (1 MiB per byte field, 4096 list items,
RaptorQ at most 10000 source symbols for encoding, 24-bit symbol ids) are harness errors, as in the other
harnesses.

## Operations

| Op | Context | Effect | C++ behind it |
|---|---|---|---|
| `public_key` | `public_key` (TL `PublicKey`) | key type, short id, canonical bytes, `serialized_size`, ADNL id text when it is an ADNL id | `PublicKey(tl)`, `compute_short_id`, `AdnlNodeIdFull::create`, `AdnlNodeIdShort::serialize` |
| `private_key` | `private_key` (TL `PrivateKey`) | key type, public key, short id | `PrivateKey::compute_public_key`, `compute_short_id` |
| `sign` | `private_key`, `message` | signature | `Decryptor::sign` (Ed25519 is deterministic; AES refuses; unenc signs with nothing) |
| `verify` | `public_key`, `message`, `signature` | `verified` or a refusal | `Encryptor::check_signature` of every wire key type (Ed25519, AES, unenc, overlay) |
| `encrypt` | `public_key`, `data` | ciphertext | `Encryptor::encrypt` for AES, unenc and overlay; Ed25519 draws a fresh ephemeral key, so only its receive side is pinned |
| `decrypt` | `private_key`, `ciphertext` | plaintext or a refusal | `Decryptor::decrypt` (Ed25519, AES, unenc, overlay) |
| `shared_secret` | Ed25519 `private_key`, `public_key` | the shared secret | `td::Ed25519::compute_shared_secret` (channels and Ed25519 encryption) |
| `adnl_id` | `id` or `text` | id and text form | `AdnlNodeIdShort::parse`, `serialize` |
| `adnl_address_list` | `address_list` (TL) | version, dates, priority, flags, each address, QUIC addresses, `serialized_size`, canonical bytes | `AdnlAddressList::create` |
| `adnl_message` | `message` (TL `adnl.Message`) | type, fields, the node's `size()` accounting, canonical bytes | `AdnlMessage(tl)` |
| `adnl_packet` | `contents` (TL `adnl.packetContents`) | every extracted field, `to_sign`, canonical bytes, `signature_check` against a full source | `AdnlPacket::create` (with `run_basic_checks`), `to_sign`, `tl`, the full source's encryptor |
| `adnl_datagram` | receiver `private_key` (Ed25519), `datagram` | the received packet, or the refusal the node logged | the node's inbound path run in-process: `AdnlPeerTableImpl::receive_packet`, `AdnlLocalId::receive` (admission, keyring decryption), `receive_decrypted_packet` and the new `AdnlPeerPairImpl::receive_packet` up to its signature check, for a receiver that knows no peer yet (see below) |
| `adnl_channel` | local channel private key, peer channel public key, local and peer ids, optional inbound `datagram`, optional packet to `send` | `in_id`, `out_id`, the decrypted packet or its refusal, the datagram the channel emits | `AdnlChannel::create`, the node's peer table routing the datagram to `AdnlChannelImpl::receive`, `AdnlChannelImpl::send_message` on a single-threaded scheduler, with recording doubles for the peer pair, the connection and the socket |
| `preauth_source` | `address` | the source key | `preauth_source` (IPv4 address, IPv6 /64, port cleared) |
| `preauth_gate` | `max_sources`, source/process/local budgets, `events` (admit an address, release a ticket) | per event `admitted`, `released` or a refusal class; table size | `PreauthGate::admit`, `DecryptBudget` (periods of at least 60 s, so no token refills while a context runs) |
| `overlay_id` | `name` | short id, the overlay public key | `OverlayIdFull::compute_short_id` |
| `overlay_node` | `node` (TL `overlay.node`) | ids, flags, version, `to_sign`, signature check, member flags, member certificate, canonical bytes | `OverlayNode::create`, `check_signature`, `OverlayMemberFlags` |
| `overlay_certificate` | `certificate`, `overlay_id`, `issued_to`, `unix_time`, `size`, `is_fec` | issuer, `to_sign`, `allowed`/`need_check`/`forbidden`, canonical bytes | `Certificate::create`, `to_sign`, `check` |
| `overlay_member_certificate` | `certificate`, `node`, `now` | fields, `to_sign`, the issuer's signature check, `expired` at `now` | `OverlayMemberCertificate(tl)`, `to_sign_data`, `is_expired(now)` (expiry at most 1000000000 or never, so the verdict cannot change with the clock) |
| `overlay_member_flags` | `flags`, `plumtree_enabled`, `original_sender` | validity, receive predicates, `public_flags` | `OverlayMemberFlags` |
| `overlay_privacy_rules` | unauthenticated size limit, flags, authorized keys, source, size, `is_fec`, `is_any_sender` | `allowed`/`need_check`/`forbidden`, largest broadcast | `OverlayPrivacyRules::check_rules`, `max_broadcast_size` |
| `overlay_broadcast` | `now`, overlay `name`, `members` (Ed25519 keys), `mode` (`simple`, `fec`, `twostep`, `plumtree`), privacy rules; optional `broadcast` member 0 sends (`data`, `flags`, `fec`); optional `inbound` messages (`src` id, `dst` member, `message`) | every message the members emitted (source, destination, transport, TL type, bytes), what each member's application received (source key, data digest, extra), the drops the overlay logged | `OverlayManager` and one `OverlayImpl` per member, run in-process (see below) |
| `fec_type` | `fec_type` (TL `fec.Type`) | parameters, whether its decoder can be created, canonical bytes | `fec::FecType::create`, `create_decoder` |
| `fec_encode` | `algorithm` (raptorq, online, round_robin), `data`, `symbol_size`, `symbol_ids` | parameters, the symbols | `td::fec::*Encoder` |
| `fec_decode` | `algorithm`, parameters, `symbols`, optional `regenerate` ids | per-symbol verdict, decoded data (digest; bytes up to 4 KiB) or the refusal, symbols of the returned encoder | `td::fec::*Decoder` (`add_symbol`, `try_decode`) |
| `rldp2_fec_helper` | `symbols_count`, `received_symbols_count` | the sender's FEC target and remaining count | `rldp2::FecHelper` |
| `rldp2_budget` | `data_size`, `symbol_size`, `symbols_count` | decoder reservation and solver bytes (null on overflow), part size, symbol size, default MTU | `rldp_decoder_reservation_bytes`, `rldp_solver_working_bytes` |
| `rldp2_receive` | raw datagrams, optional budget, MTU, outstanding requests | per datagram: delivered transfers, completed parts, `rldp2.complete` answers; open and completed transfer counts | `RldpConnection::receive_raw` and `run` on a fresh connection |
| `rldp2_send` | `transfer_id`, `data` | the datagrams of the first run (framing fields, digests) | `RldpConnection::send` and `run` |

`rldp2_receive` leaves out `rldp2.confirm` acknowledgements: when they are due depends on the clock.
`rldp2_send` reports one run only, which is a function of the data: every packet of a run is sent at one
timestamp.

## Overlay broadcasts

`overlay_broadcast` (`ref/net-broadcast.cpp`) runs the node's `OverlayManager` and one `OverlayImpl` per
member of a fixed-member overlay, all on one single-threaded scheduler with one keyring holding every
member's key. The stand-ins are at the network edge only: an ADNL that records what an overlay sends and
hands it to the overlay manager of its destination member through the subscription the manager made (as
`AdnlLocalId::deliver` does), and the sender two-step and Plumtree broadcasts go through. Member 0 sends
through `send_broadcast_ex` (or `send_broadcast_fec_ex` with `fec`, `send_broadcast_plumtree(_fec)` in
`plumtree` mode, where the simple broadcast's id is the SHA-256 of its data, the caller's choice); the
`inbound` messages are handed to their member as from the given ADNL id. Every emitted message is
delivered in order until the members are idle. The members' applications accept every broadcast they are
asked to check.

The overlay reads the wall clock for broadcast dates, their 20-second acceptance window and certificate
expiry. The reference library is linked with `--wrap=_ZN2td6Clocks6systemEv` (`CMakeLists.txt`,
`parts/fuzz.cmake`), and `ref/net-node.cpp` defines the wrapper: while an `overlay_broadcast` context
runs it returns the context's `now`, otherwise the real clock. So the dates, the bytes each broadcast
signs, its signature and its id are functions of the context, and the frozen effects carry them
byte-exact: an emitted broadcast is its full TL object including the signature, and an id the receiver
recomputes is checked through the signature it verifies.

Bounds, from what the node itself fixes rather than the context: with more than one neighbour the
simple, FEC and Plumtree paths choose neighbours at random, so those modes take exactly two members
(two-step broadcasts go to every member in a fixed order: two to eight members); the FEC sender emits
four symbols at once and the rest on a 10 ms timer, so an old-style FEC broadcast is at most 1535 bytes
(four symbols are all it sends); `send_broadcast_ex` aborts on a simple broadcast above 768 bytes (its
callers pick the FEC path above that), so a larger one is a harness error. Plumtree with one neighbour
pushes lazily (`overlay.broadcastPlumtreeIHave`); the receiver's repair request waits for a timer, so
only the announcement is pinned.

Drops: a broadcast the overlay refuses with an error is logged (`Failed to process broadcast ...`), as
are messages from non-members of a private overlay; `drops` lists their classes in log order. Refusals
the overlay reports as not ready are not logged at all (a date outside the window, a duplicate, a source
the privacy rules forbid): those show as no delivery and no drop.

## Refusal classes

| Class | Node messages | First fixture reaching it |
|---|---|---|
| `tl_truncated` | `Not enough data to read` | `adnl-address-list/truncated` |
| `tl_trailing_data` | `Too much data to fetch` | `adnl-address-list/trailing` |
| `tl_unknown_constructor` | `Unknown constructor found`, `Wrong constructor found` | `adnl-address-list/unknown-address` |
| `tl_bad_length` | `Wrong vector length` | `adnl-address-list/negative-count` |
| `tl_negative_flags` | `can't be negative` | `adnl-packet/negative-flags` |
| `datagram_short` | `message too short` | `adnl-channel/bob-short` |
| `unknown_destination` | `unknown dst` | `adnl-datagram/other-destination` |
| `ciphertext_short` | `message is too short` | `adnl-channel/bob-ciphertext-short` |
| `digest_mismatch` | `sha256 mismatch after decryption` | `adnl-channel/bob-body-flipped` |
| `invalid_signature` | `Wrong signature` | `adnl-datagram/unsigned` |
| `degenerate_public_key` | `Failed to compute modulo inverse`, `Failed to compute shared secret` | `adnl-channel/peer-key-identity` |
| `signing_unsupported` | `can no sign channel messages` | `keys/verify/aes` |
| `key_unusable` | `Fail decryptor`, `Fail encryptor` | `keys/sign/overlay` |
| `encryption_unsupported` | `overlay id can not be used for encryption` | `keys/encrypt/overlay` |
| `overlay_signature_invalid` | `overlay signature must be empty`, `overlay update rule should be` | `keys/verify/overlay-key-description-signed` |
| `not_ed25519` | `bad public key` | `adnl-packet/source-not-ed25519` |
| `adnl_id_length` | `Wrong length of adnl id` | `adnl-id/parse/short` |
| `adnl_id_prefix` | `Invalid first byte` | `adnl-id/parse/prefix` |
| `adnl_id_checksum` | `Hash mismatch` | `adnl-id/parse/checksum` |
| `adnl_id_encoding` | `Wrong character in the string`, `Wrong padding`, `Nonzero padding` | `adnl-id/parse/not-base32` |
| `packet_bad_flags` | `bad flags` | `adnl-channel/bob-bad-flags` |
| `packet_message_flags` | `both flags one_message and mult_messages`, `flag one_message is set` | `adnl-packet-flags/flags-00cc` |
| `packet_source_mismatch` | `source and short source mismatch` | `adnl-packet/source-mismatch` |
| `packet_address_list_empty` | `bad addr list` | `adnl-packet/address-list-empty` |
| `address_list_oversize` | `too big addr list` | `adnl-address-list/nine-udp` |
| `source_missing` | `src not set` | `adnl-datagram/no-source` |
| `source_unknown` | `no full src in packet` | `adnl-datagram/short-source-only` |
| `channel_source_mismatch` | `bad channel packet destination` | `adnl-channel/bob-wrong-source` |
| `source_limit` | `pre-authentication source limit exceeded` | `preauth/gate/source-limit-all-in-flight` |
| `rate_limited` | `rate limit exceeded` | `preauth/gate/rate-limit` |
| `process_budget` | `process decrypt budget exceeded` | `preauth/gate/process-budget` |
| `local_budget` | `local decrypt budget exceeded` | `preauth/gate/local-budget` |
| `overlay_node_invalid` | `invalid overlay node flags or certificate` | `overlay-node-rtos/flags-4` |
| `overlay_unknown_source` | `in private overlay from unknown source` | `overlay-broadcast-inbound/simple/from-non-member` |
| `broadcast_disabled` | `broadcasts are not enabled` | `overlay-broadcast-inbound/twostep/to-simple-overlay` |
| `fec_symbol_size_small` | `symbol_size below floor` | `fec-type/raptorq-symbol-767` |
| `fec_symbol_size_large` | `symbol_size is too big` | `fec-type/raptorq-symbol-2049` |
| `fec_too_many_symbols` | `too many symbols`, `K is too big` | `fec-type/raptorq-k-56404` |
| `fec_symbols_count` | `wrong symbols_count` | `fec-type/raptorq-count-low` |
| `fec_not_raptorq` | `only RaptorQ is allowed` | `fec-type/online` |
| `fec_negative` | `Narrow cast failed` | `fec-type/raptorq-negative-size` |
| `symbol_length` | `Symbol has invalid length` | `fec-online/decode/wrong-symbol-length` |
| `symbol_id_range` | `Too big symbol id` | `fec-raptorq/decode/symbol-id-2-pow-24` |
| `need_more_symbols` | `Need more symbols`, `Not ready` | `fec-online/decode/s768-n1-source` |

`runner/test_net.py` checks that the C++ table, the validator's `REASONS` and the schema's `$defs/reason`
name the same classes, and that every class but `unclassified` is reached by a frozen fixture.

A drop on the inbound ADNL path has no status of its own: the node logs it (`dropping IN message ...`)
and returns. `adnl_datagram` therefore runs the node's own peer table, keyring and local id on a
single-threaded scheduler (`ref/net-node.cpp`; the only stand-in is the socket, which hands the datagram
to the peer table from 192.0.2.1:3000 for every address category), captures the node's log while the
context runs, and classifies the text after the first `dropping IN message` by the table above
(`message too short`, `unknown dst`, `src not set`, `no full src in packet` and the statuses the node
appends). The datagram is received once the new peer pair has run its checked-packet handler, which is
the first step that gives the pair a reinit deadline in its stats (`AdnlPeerTable::get_stats`); what
the pair then does with the packet (reinit dates, sequence numbers, addresses, messages) is not part of
the effect. The receiver's local id is an Ed25519 key (`add_id_ex` requires one); any other key is a
harness error. Each context gets a fresh peer table, keyring and local id; the node's process-wide
decrypt budget (a burst of 4096, refilled at 4096 per second) is shared by all contexts of one process,
which a run of a few thousand datagram contexts per second would reach.

`adnl_channel` routes its inbound datagram through the same peer table: the channel is registered under
its inbound id (`register_channel`, as the peer pair that creates it does), the socket stand-in hands the
datagram to the table, and the channel's own `receive` decrypts it and passes the packet to the recording
peer pair, or logs the drop. Both datagram and channel routing therefore run the node's
`AdnlPeerTableImpl::receive_packet`; a datagram whose first 32 bytes name neither a local id nor a
registered channel is the node's `unknown dst` (`adnl-channel/bob-unknown-channel`, class
`unknown_destination`).

Not reachable through the wire and therefore not in the table: `Too big string found` (a 64-bit length
above the address space, which a 64-bit build never sees), `flag one_message is set, but the number of
messages is not 1` (one message is all the flag can parse; the class is shared with the reachable flag
refusal), FecType's `too many symbols` for a 768-byte symbol (`data_size` is a 32-bit int, below
768 * 2^24; `K is too big` from the decoder carries the class instead), RLDP2's `too big part` and `part
decoder size overflows` (the part size check before them already bounds the part).

## Families (`vectors/net/fixtures/`)

1,290 fixtures, 5.5 MB. Every context is built by `migrate/net_contexts.py contexts`; signatures,
ciphertexts, channel datagrams, the bytes a packet signs and FEC symbols come from the reference itself,
so a context is valid or invalid exactly where it is written to be. Randomness is a fixed seed: running
`contexts` twice gives byte-identical files.

| Family | Source | Fixtures | Contexts |
|---|---|---|---|
| `keys` | authored | 100 | every key type through public/private key, sign, verify, encrypt, decrypt; flipped and truncated signatures and messages, s above the group order, a non-point key; overlay key descriptions; AES and Ed25519 ciphertexts of 0..1500 bytes and their mutations; shared secrets both ways, with itself, the neutral and a low-order point |
| `ed25519-rfc8032` | `migrated:rfc8032/ed25519-sign` | 192 | the first 64 RFC 8032 sign vectors (vendored under `third-party/`): public key, signature and verification |
| `adnl-id` | authored | 10 | text forms of fixed ids; wrong length, checksum, prefix and alphabet |
| `adnl-id-test-adnl` | `migrated:test/test-adnl` | 2 | the id of `test/test-adnl.cpp` both ways |
| `adnl-address-list` | authored | 19 | each address kind, reordering on re-serialization, version -1, negative fields, the 128-byte limit at 8/9 UDP addresses and at a 59/60/61-byte tunnel key, truncation |
| `adnl-message` | authored | 16 | each message type, 253/254-byte strings, negative part sizes, truncation |
| `adnl-packet` | authored | 24 | signed packets with each field, the priority flag, empty and long rand, unsigned and wrongly signed packets, each packet check |
| `adnl-packet-flags` | authored | 384 | every combination of the six source, message and address-list flags with six seeded combinations of the seven others; full sources signed |
| `adnl-datagram` | authored | 13 | signed datagrams to a local id; other destination, short datagram and ciphertext, tampering, no or short-only source, unsigned and wrongly signed packets |
| `adnl-channel` | authored | 16 | both ends of one channel and the same-id case; one end's emitted datagram received by the other; unknown channel, short, tampered, bad packets, wrong source; non-point and neutral peer keys |
| `preauth` | authored | 18 | source keys of IPv4, IPv6 and mapped addresses; rate, source-table, least-recently-used replacement, IPv6 /64 sharing, process and local budgets |
| `overlay-id` | authored | 5 | names of 0..254 bytes and a shard public overlay id |
| `overlay-node` | authored | 16 | flags 0..3 signed, invalid flags, unsigned or wrongly signed nodes, a non-Ed25519 id, member certificates good and bad |
| `overlay-node-rtos` | `migrated:rtos/overlay-node` | 15 | the RTOS `tos-overlay-node-vectors.txt` node and its toSign framing; its flag tests (0..3 valid and signed, 4 and -1 refused, flipped flags and signatures) |
| `overlay-certificate` | authored | 28 | V1 at 768/769/1 MiB, size and expiry boundaries, FEC, V2 flags 0..3, V2 with default flags signed as V1 or V2, bad signatures, unenc/overlay/AES issuers, empty |
| `overlay-member-certificate` | authored | 15 | flags and slots, other node, the 3-second expiry grace, empty, unenc issuer |
| `overlay-policy` | authored | 43 | member flags 0..7 and high bits under both plumtree settings; privacy rules for authorized keys and strangers |
| `fec-type` | authored | 20 | RaptorQ at 1, 768, 769, 2048-byte symbols, an RLDP part, K = 56403/56404, the largest data size, empty, symbol size 767/0/2049, wrong counts, negative values, other codes, truncation |
| `fec-raptorq` | authored | 44 | encode and decode for 8 size/symbol combinations from source symbols, repair symbols only, one symbol short; ids up to 2^24-1; wrong lengths, duplicates, a corrupted symbol; the decoder's encoder regenerating symbols |
| `fec-raptorq-sweep` | authored | 120 | 60 seeded sizes, symbol sizes and symbol subsets, encoded and decoded |
| `fec-online` | authored | 58 | as `fec-raptorq`, with more symbols, since the online code needs more than K |
| `fec-round-robin` | authored | 42 | as `fec-raptorq` |
| `overlay-broadcast` | authored | 18 | member 0's simple broadcasts (768 bytes, empty, over the unauthenticated size, an authorized key, AnySender with and without authorization, a source the application checks), FEC broadcasts of 50 and 1500 bytes and without the FEC flag, two-step broadcasts to 2, 6 and 8 members (simple and FEC, 512 bytes just below the FEC threshold), an old broadcast in a two-step overlay, Plumtree simple and FEC announcements |
| `overlay-broadcast-inbound` | authored | 27 | messages a member receives, built from what the node sent: simple broadcasts replayed (once and twice), with a flipped signature, data or source key, from a non-member, re-dated 19/20/21 seconds off and re-signed, re-signed as AnySender, with 768- and 769-byte data, truncated, into a two-step overlay; FEC parts replayed, with a flipped signature or data hash, to an overlay without the FEC flag; two-step broadcasts replayed, tampered, into a simple overlay, from a non-member; Plumtree announcements replayed, tampered, into a simple overlay |
| `rldp2` | authored | 45 | FEC helper and budget arithmetic; the sender's first run for 1..7680 bytes; the receiver on in-order, reversed and repair-only symbols, duplicates after completion, two transfers, the default MTU and a raised one, request limits, other codes, symbol sizes, part indices, negative fields, short symbols, out-of-range ids, stray complete/confirm datagrams, garbage, an exhausted budget |

Cross-checks (`migrate/net_contexts.py check`, ctest `conformance-net-crosscheck`): every expectation in
`metadata.note` holds (the RFC 8032 public keys and signatures, the `test/test-adnl.cpp` id, the RTOS node
bytes, and the verdict each authored negative is written for); the RTOS toSign vector equals the node's
toSign framing apart from the id it signs for; AES ciphertexts decrypt to what was encrypted; both ends of
a channel agree on its ids and the packet one end receives is the one the other sent; decoding returns the
encoded data and a decoder's encoder regenerates the encoder's symbols; each RLDP2 datagram built for the
receiver is byte-identical to the one the node's sender emits, and the transfer arrives intact; every
broadcast reaches exactly the members its note names (once each) with the digest of the data sent, and
an inbound replay is byte-identical to the message the sending fixture emitted.

Regenerating (from a clean, committed reference build; `create` runs `runner/conformance.py create` per
family with its source and keeps every hex field inline):

```
python3 test/conformance/migrate/net_contexts.py contexts --reference build/test/conformance/conformance-ref-cli \
    --rtos <RTOS checkout> --out <scratch> [--only <family> ...]
python3 test/conformance/migrate/net_contexts.py create --reference build/test/conformance/conformance-ref-cli \
    --contexts <scratch> test/conformance/vectors/net [--only <family> ...]
python3 test/conformance/migrate/net_contexts.py check test/conformance/vectors/net
```

The RTOS file is `adnl/src/overlay/testdata/tos-overlay-node-vectors.txt` of the RTOS repository; only
`overlay-node-rtos` needs it, and `--only` limits a run to the named families (the two broadcast families
are built together).

## Behaviour the fixtures pin that a peer may not expect

- The 768-byte bound of simple broadcasts holds for the sender only: a received simple broadcast of 769
  bytes is accepted and relayed (`overlay-broadcast-inbound/simple/data-769-resigned`).
- An overlay message that does not parse as a broadcast object is handed to the application as a plain
  message (`overlay-broadcast-inbound/simple/truncated`).
- Ed25519 and AES encryption authenticate nothing but the SHA-256 of the plaintext: an empty plaintext
  decrypts under any key (`keys/decrypt/ed25519-0-other-key`). The packet that follows is what a receiver
  then checks.
- `Encryptor::check_signature` of an unenc key accepts every signature, and so do certificate checks whose
  issuer is an unenc key (`keys/verify/unenc-accepts-anything`, `overlay-certificate/issuer-unenc`,
  `overlay-member-certificate/issuer-unenc`); the overlay accepts a certificate only from an issuer it
  trusts, which is checked outside these functions.
- A V2 overlay certificate whose flags equal the V1 default for its size is signed and re-serialized as V1
  (`overlay-certificate/v2-default-flags-signed-as-v2`, `v2-flags-3`).
- An RLDP2 symbol the decoder refuses ends the transfer with an error and marks it completed
  (`rldp2/receive/symbol-short`).
- The round-robin encoder cuts its last symbol short when the data is not a multiple of the symbol size,
  and the round-robin decoder refuses a short symbol, so such data never decodes
  (`fec-round-robin/decode/s768-n1-source`). Round-robin and online codes are refused by
  `FecType::create`, so no peer can make a node use them.

## Not covered, and why

- Broadcasts between more than two members on the simple, FEC and Plumtree paths (random neighbour
  choice), FEC broadcasts above four symbols and Plumtree repair (timers), the overlay's not-ready
  refusals (not logged), certificate-carrying broadcasts in public overlays and the FEC short form.
- The peer pair's acceptance of a checked packet (reinit dates, seqno windows, address-list updates),
  `adnl.message.part` reassembly and the split of large messages into parts: state of
  `AdnlPeerPairImpl`, an actor bound to a network manager and a DHT. Message part decoding is covered.
- RLDP2 acknowledgements, retransmission, pacing and congestion control: functions of the clock.
- RLDP2 transfers of more than one 2 MB part: a context would carry 4 MB of hex; the part split and
  part-size checks are reached through their single-part boundaries.
- QUIC transport, DHT records, the RLDP query layer (`rldp.query`/`rldp.answer`) and the Simplex
  consensus messages (the `consensus` harness covers votes, certificates and session identity).
