# Overlay node receive policy

## Single node description

`overlay.node` is the only node description used by peer exchange, public DHT
discovery and the overlay discovery cache. It carries the public key, overlay
ID, flags, timestamp, signature and membership certificate. Its signed preimage
always includes flags, including when they are zero. Public nodes carry the
empty membership certificate; semiprivate overlays validate their certificates.

| Flag | Meaning |
| --- | --- |
| `1` (`DoNotReceiveBroadcasts`) | Refuse ordinary and Plumtree broadcasts. |
| `2` (`DoNotReceivePlumtreeBroadcasts`) | Refuse Plumtree data and IHAVE; ordinary broadcasts remain enabled. |

Unknown flag bits are rejected. A newer signed timestamp updates a peer's
policy; equal or older timestamps cannot replace it. Public Plumtree forwarding
requires a fresh full node description.

Public original senders and nodes without a Plumtree receiver advertise flag
`2`. They can still publish to observers and serve repair queries. A receiver
can grant a larger QUIC receive budget for its upstream sender regardless of
that sender's own receive policy. The default 1,024-byte budget is unchanged.

## Development upgrade

This wire format replaces the unreleased node description formats. Upgrade all
development nodes together; mixed old/new nodes are not supported. Invalid
overlay discovery-cache entries are ignored and rediscovered. This change does
not require deleting chain databases, keys or Genesis state.

## Regression boundaries

| Boundary | Check |
| --- | --- |
| Signed flags, serialization, freshness and old-format rejection | `test-overlay-peer-cleanup` |
| Two public publishers and one observer, Simple/FEC/repair, ordinary broadcasts, shared receive budgets and invalid cache startup | `test-overlay-plumtree-policy` |
| Public DHT signature validation and updates | `test-dht` and Rust `test_dht::dht_session` |
| Rust signed policy and semiprivate certificate handling | `receive_policy_tests` and `test_overlay_semiprivate` |
| Plumtree loss and partition recovery | CTest `plumtree-graph-sim-*` scenarios |
| QUIC oversize rejection and response deadline | `test-quic-sender` size-limit and partial-response tests |

The three-node forwarding regression uses real overlay actors and signatures
with a deterministic simulated transport. It does not replace a deployed-node
QUIC regression. Removing the Plumtree-only forwarding guard makes that test
fail because it observes data sent back to publishers; making invalid cache
decoding fatal makes the same test fail at startup.
