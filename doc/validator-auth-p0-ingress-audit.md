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
     admission_waiters_ < max_admission_waiters(), 0..50000                 BEFORE
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
| per-peer rate | 30 per 10 seconds | **every remote sender**, attributed or not |
| message size | `ext_msg_limits.max_size` | everyone |
| checks in flight | 192, over 24 workers | everyone |
| admission queue | up to 50,000, sized from measured completion rate | everyone |
| per-destination rate | 30 per 10 seconds | applied after the work |

The per-peer limiter is the only one that is per-sender, and it used to have a
case that was not bounded at all:

```cpp
bool ExtMessagePool::admit_source(const td::optional<PublicKeyHash> &source_peer, td::Timestamp now) {
  if (!source_peer) {
    return true;
  }
```

Two things about that have since changed, and both are in the tree.

An earlier revision of this document read the unbounded case as the one a
hostile sender is most likely to be in. Tracing every path that reaches this
function does not support it, and the claim is withdrawn. What each submission
path supplies:

| path | source |
| --- | --- |
| public overlay, `FullNodeShardImpl::process_broadcast` | the broadcasting peer, always |
| custom overlay, `FullNodeCustomOverlay::process_broadcast` | the broadcasting peer, always, and only from an authorized sender in `msg_senders_` |
| ADNL query, `ValidatorManagerImpl::run_ext_query` | the querying node |
| full node master, `FullNodeMasterImpl::process_query` | the querying node |
| validator engine ADNL entry | the querying node |
| JSON-RPC submission, the five `send_attributed_liteserver_query` sites | a per-client identity derived from the resolved client address |

The JSON-RPC path is worth naming, because it is the one that already answered
this question for itself. It does not forward an absent source: it hashes the
resolved client address into a stable id of its own, so that submissions over
HTTP meet the same window the ADNL path has always had. Its read queries do
carry no source, but a read query never reaches this function.

And the unbounded case no longer exists. The source is no longer an optional
peer but a sum of a remote peer and a local origin, so absence is not
representable and the limiter answers for both cases by name:

```cpp
return std::visit(td::overloaded(
                      [&](const RemotePeer &remote) { return admit_remote_peer(remote.peer, now); },
                      [&](const LocalOrigin &) { return true; }),
                  source);
```

The one path that used to reach the unbounded case was a query whose ADNL
identity is zero, which the manager turned into an absent source. It is now a
remote peer with an unattributed identity, so those clients share one limiter
bucket rather than sharing an exemption. That is a shared bucket and not a good
identity: unrelated unattributed clients throttle each other, which is a
conservative failure rather than a correct one, and improving it means giving
the transport something better to attribute by.

The local case is exempt, as a locally-originated submission has always been.
That exemption is now stated where it is decided rather than reached by
omission, and it is provenance rather than trust: whether an in-process entry
should be metered is a transport policy question that the type deliberately does
not answer.

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

## Whether a global admission limiter is missing

The question was whether the pool needs a global admission CPU token bucket on
top of the per-sender window. It does not, and the reason is that it already has
a global admission control which nobody had described as one.

`max_admission_waiters()` does not return a constant. It sizes the queue from
the completion rate the pool has been measuring, so that waiting stays under
`MAX_ADMISSION_QUEUE_DELAY`, and refuses beyond it -- before the expensive
check, like every other bound here:

```
cap = measured completions per second * 5 s, capped at 50000
```

That is a feedback controller whose control variable is throughput. A CPU token
bucket would be a second controller for the same variable, set by hand, and the
two would disagree the first time the machine changed.

What arrives at the expensive stage is bounded before that. The per-sender
window is thirty per ten seconds, so N senders can put 3N checks per second in
front of the workers:

| senders | reaching the expensive stage |
| ---: | ---: |
| 1 | 3/s |
| 10 | 30/s |
| 100 | 300/s |

and the attacker-controlled part of one check is bounded too: opening an
arriving container costs 44 microseconds at a kilobyte and 2,442 at the 64 KiB
admission ceiling, whether the bytes are repeated or distinct.

### What was wrong is the floor, not the absence of a limiter

The clamp's lower bound contradicted the rule above it. The cap is derived from
a delay, but the floor was a count, so below 512/5 = 102.4 completions per
second the floor won and the delay it was derived from was no longer what was
enforced:

| completions | cap | what a full queue then implied |
| ---: | ---: | ---: |
| 1000/s | 5000 | 5.0 s |
| 102.4/s | 512 | 5.0 s |
| 50/s | 512 | 10.2 s |
| 10/s | 512 | 51.2 s |
| 1/s | 512 | 512 s |

The departure grew exactly as the node slowed, which is the condition the bound
exists for. A queue sized for five seconds admitted over eight minutes of work
at one completion per second.

**The floor is removed.** Choosing a replacement would have meant choosing the
slowest throughput at which a node should still accept a queue -- a number from
a production machine rather than from this reasoning -- and no such number was
needed once what the floor was actually covering had been found.

It was covering two things, and only one of them was the start. The rate does
not begin at zero but at an optimistic estimate, so the first window is bounded
by that estimate and the floor was never what admitted the first burst. The
other was idleness, and that one was real: the rate was an average of
completions over wall-clock seconds, so a pool nobody was sending to decayed
toward zero for want of traffic rather than for want of capacity, and removing
the floor alone would have made such a pool shed the next burst it used to
queue.

A window in which nothing completed has not measured a throughput of zero; it
has measured nothing. It is no longer folded in, so an idle pool keeps the
throughput it last demonstrated and a slow one is measured as slow. That is
what makes removing the floor a correction rather than a trade: the estimate now
means what the cap reads it as meaning.

What remains is the delay's own statement at every rate: the queue is however
many checks finish in `max_admission_queue_delay` at the rate the pool is
achieving, up to the ceiling. A pool completing nothing admits no queue, which
is the same rule rather than a new refusal -- the checks already in flight still
run and still release their slots, and a sender told "not ready" at once is
better served than one left waiting for a delay nobody bounded.

The rule and the two constants it reads now sit together in
`validator/impl/ext-message-admission.h`, apart from the pool, so the arithmetic
can be stated as itself; the ingress suite asserts that a full queue never
implies more than the delay at any of seven rates, that the ceiling still holds,
and that a rate of zero, a negative rate and a rate that is not a number all
admit nothing.
