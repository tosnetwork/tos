# The path a hostile external message takes before anything charges for it

This is an audit, not a design. It traces what happens to an external message
between arriving on a socket and reaching the registry authority, and records
what bounds exist on that path, where they sit relative to the expensive work,
and which of them a sender can decline to be subject to.

It exists because a bound on the work one message can cause is not a bound on
the work a sender can cause. The first is settled: a container declares how much
it expands to before any of it is unpacked, and admission now refuses more than
sixty-five thousand five hundred and thirty-six logical bytes per expansion. The
second is what this traces.

## The path

Two ingress kinds, one destination:

| origin | entry |
| --- | --- |
| overlay broadcast | `full-node-shard.cpp:186` → `new_external_message_broadcast` |
| custom overlay broadcast | `full-node-custom-overlays.cpp:153` → same |
| liteserver `sendMessage` | `liteserver.cpp:564` → `new_external_message_query` |

All three converge on `ExtMessagePool::check_add_external_message`, and nothing
else calls it. There is no separate validator and collator ingress: both consume
what this pool admitted. Where they do differ -- `collator.cpp` and
`validate-query.cpp` each assembling their own authority -- is downstream of
admission and operates on messages the pool already accepted.

Inside the pool, in order:

```
check_add_external_message
  1  admit_source(source_peer)              per peer, 30 per 10 seconds     BEFORE
  2  data.size() <= ext_msg_limits.max_size                                 BEFORE
  3  inflight_checks_ < MAX_INFLIGHT_CHECKS = 8 * 24 = 192                  BEFORE
     admission_waiters_ < max_admission_waiters(), 512..50000               BEFORE
  4  ExtMessageChecker::check, on one of NUM_CHECKERS = 24 workers
       offer_validator_auth -> assemble_registry_authority
         -> NativeEvidence::open            <- the allowance from B1, once
       run_message
         VM run, no log, with the assembled host
         if it failed: clone_for_execution -> fresh host -> VM run with log
  5  MAX_EXT_MSG_PER_ADDR, 30 per 10 seconds per destination                AFTER
  6  ext_messages_hashes_ / ext_messages_hashes_norm_                       AFTER
```

## How many expansions one message can cause

**One evidence opening whether the first VM run succeeds or fails.** The logging
retry still asks for an authority a second time:

```cpp
auto status = run_message_on_account(..., *exec_config.nolog, authority());
if (status.is_ok()) return status;
...
auto status_with_log = run_message_on_account(..., *exec_config.log, authority());
```

What changed is what that factory means. Admission runs before `run_message` and
produces one `NativeConfigTransaction`. Its parsed evidence, committee, witnessed
history, proposal and accepted prefix are held as immutable material. The first
VM run uses the assembled host. If the run fails, `clone_for_execution()` builds
a new context, reader and host over that same admitted material. The rebuilt
account therefore meets a host with fresh staged state and a fresh work allowance,
without parsing the attacker-controlled evidence again.

One opening still expands at two points -- the authorizations blob and the
attachments -- and each point is bounded independently. A failed hostile message
therefore causes the same two bounded expansion points as a successful message,
not four.

A source guard holds both halves of that property. Moving admission back inside
the retry factory is rejected, and replacing the clone with the already-used
host is rejected separately. Those regressions otherwise leave ordinary
functional answers unchanged.

## Whether repeating a message is cheaper than the first time

**No. It is exactly as expensive.**

The pool keeps two hash sets, `ext_messages_hashes_` and its normalized
counterpart. Both are mempool membership: an entry appears when a message is
*added to the mempool*, which happens after the check and only for messages the
check accepted. A rejected message is never recorded, so nothing recognises it
when it arrives again, and `check_add_external_message` consults neither set
before running the checker.

So the question of whether re-writing a container defeats suppression does not
arise. There is no suppression of rejected messages to defeat. A sender can send
one hostile message unchanged, as many times as the bounds below allow, and pay
the full check every time.

The normalized hash is worth noting for later: being normalized, it is the kind
of identity that would not be defeated by re-serializing the same logical
message. It is not used for this.

## What actually bounds a sender

| bound | value | applies to |
| --- | --- | --- |
| per-peer rate | 30 per 10 seconds | **only a sender with a peer identity** |
| message size | `ext_msg_limits.max_size` | everyone |
| checks in flight | 192, over 24 workers | everyone |
| admission queue | 512 to 50,000, sized from measured completion rate | everyone |
| per-destination rate | 30 per 10 seconds | applied after the work |

The per-peer limiter is the only one that is per-sender, and it has a case that
is not bounded at all:

```cpp
bool ExtMessagePool::admit_source(const td::optional<PublicKeyHash> &source_peer, td::Timestamp now) {
  if (!source_peer) {
    return true;
  }
```

An earlier revision of this document read that as the case a hostile sender is
most likely to be in. Tracing every path that reaches this function does not
support it, and the claim is withdrawn. What each submission path supplies:

| path | source |
| --- | --- |
| public overlay, `FullNodeShardImpl::process_broadcast` | the broadcasting peer, always |
| custom overlay, `FullNodeCustomOverlay::process_broadcast` | the broadcasting peer, always, and only from an authorized sender in `msg_senders_` |
| ADNL query, `ValidatorManagerImpl::run_ext_query` | the querying node, unless its ADNL id is zero |
| full node master, `FullNodeMasterImpl::process_query` | the querying node |
| validator engine ADNL entry | the querying node |
| JSON-RPC submission, the five `send_attributed_liteserver_query` sites | a per-client identity derived from the resolved client address |

The JSON-RPC path is worth naming, because it is the one that already answered
this question. It does not forward an absent source: it hashes the resolved
client address into a stable id of its own, so that submissions over HTTP meet
the same window the ADNL path has always had. Its own comment says why. Its read
queries still carry no source, but a read query never reaches this function.

What is left is narrower and is an architectural ambiguity rather than a
measured public hole: the source is an `optional` with a default, so absence is
representable and means "unlimited" without anyone having chosen that. The one
residual path that reaches it is a JSON-RPC submission whose client address
resolves empty, which keeps the historical zero id. No measured public remote
path currently reaches this function without an identity.

For a sender who did reach it, what remains is the concurrency bound: 192 checks
in flight across 24 workers, with a queue in front of it. That bounds how much
work is in progress at once. It does not bound how much work is done per second,
which is what a saturation attack spends.

The per-destination limit does not help here either. It is applied after the
check, so a message refused by the check never reaches it, and the work of
refusing was already done.

## What this leaves for the fix

The first finding from the trace -- duplicate evidence admission on the logging
retry -- is closed as described above. Two wider ingress questions remain.

Rejected messages are not suppressed. The machinery to suppress them --
including a normalized hash that is representation-independent -- already exists
for accepted ones. Whether refusal is safe to cache is a separate question: a
message refused against one masterchain state may be legitimate against the
next, so any such cache is bounded by state rather than by time alone.

The per-source limiter has a case that is not bounded, but on the evidence above
it is not the case a hostile remote sender is in. The work it calls for is
therefore not a limiter but a type: the source is an `optional` with a default,
so a call site can omit provenance and silently receive the unlimited answer,
and nothing makes a new call site choose. Making provenance explicit and total
-- a remote peer or a local origin, with no third state and no default -- fixes
the ambiguity without deciding anything about transports.

Whether a local origin is exempt from the limiter is a separate transport policy
decision and is deliberately not settled by that change: local is provenance,
trusted is policy, and merging them is how an in-process convenience becomes an
unlimited external path later.

Neither remaining question requires a new registry-specific limiter, which is
the outcome this audit was run to test for.
