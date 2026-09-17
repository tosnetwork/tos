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
         -> NativeEvidence::open            <- the allowance from B1
       run_message
         VM run, no log
         if it failed: authority() again -> a second open -> VM run with log
  5  MAX_EXT_MSG_PER_ADDR, 30 per 10 seconds per destination                AFTER
  6  ext_messages_hashes_ / ext_messages_hashes_norm_                       AFTER
```

## How many expansions one message can cause

One if the message's first VM run succeeds. **Two if it fails**, because the
authority is supplied as a factory and `run_message` calls it again to repeat
the run with logging on:

```cpp
auto status = run_message_on_account(..., *exec_config.nolog, authority());
if (status.is_ok()) return status;
...
auto status_with_log = run_message_on_account(..., *exec_config.log, authority());
```

The retry is diagnostic. Its result is discarded unless it fails, in which case
its error is returned instead. What matters here is who reaches it: a legitimate
message succeeds and is assembled once; a hostile message fails by definition
and is assembled twice. The doubling applies to exactly the traffic that should
not have it.

Each assembly opens the container once, and one opening expands at two points,
each bounded. So a hostile message can cause four bounded expansions where a
legitimate one causes two.

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

The per-peer limiter is the only one that is per-sender, and it is the one with
a hole in it:

```cpp
bool ExtMessagePool::admit_source(const td::optional<PublicKeyHash> &source_peer, td::Timestamp now) {
  if (!source_peer) {
    return true;
  }
```

A message arriving without a source peer is not rate limited at all. Whether a
given transport supplies one is a property of that transport rather than of the
sender's intent, so this is not a bound a hostile sender has to work around --
it is one they may simply not be subject to.

What remains for such a sender is the concurrency bound: 192 checks in flight
across 24 workers, with a queue in front of it. That bounds how much work is in
progress at once. It does not bound how much work is done per second, which is
what a saturation attack spends.

The per-destination limit does not help here either. It is applied after the
check, so a message refused by the check never reaches it, and the work of
refusing was already done.

## What this leaves for the fix

Three things, in the order the trace found them.

The double assembly in the ingress checker is redundant rather than protective:
both calls parse the same immutable message against the same state and can only
agree. Removing it halves hostile-message cost and changes nothing else, and is
worth doing before considering any limiter, because a limiter sized against
doubled work is sized against a number we chose not to fix.

Rejected messages are not suppressed. The machinery to suppress them --
including a normalized hash that is representation-independent -- already exists
for accepted ones. Whether refusal is safe to cache is a separate question: a
message refused against one masterchain state may be legitimate against the
next, so any such cache is bounded by state rather than by time alone.

The per-source limiter has an unbounded case, and it is the case a hostile
sender is most likely to be in. Closing it is a policy decision about transports
that supply no peer identity, not a validator-auth decision, and it protects
every external message rather than only this path.

None of the three requires a new registry-specific limiter, which is the outcome
this audit was run to test for.
