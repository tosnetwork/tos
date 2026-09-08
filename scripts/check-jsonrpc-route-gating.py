#!/usr/bin/env python3
"""Check that every JSON-RPC HTTP route is accounted for by the rate gate.

The per-source budget is applied in `cached_dispatch_method`, which every
method dispatch funnels through. Routes handled directly in `on_request`
bypass that funnel, so each one has to either apply the budget itself or
be a static reply that starts no work.

This check exists because a route was added that did neither: `/readyz`
issues a liteserver query of its own and went ungated, while the unit
tests for the gate stayed green -- the gate was correct, it just was not
reached. That is not a failure a test of the gate can see, so it is
checked here instead: the route list is pinned, and adding a route makes
this fail until the new route is classified.

Run: python3 scripts/check-jsonrpc-route-gating.py
"""

import pathlib
import re
import sys

SERVER = pathlib.Path(__file__).resolve().parent.parent / "validator-engine" / "json-rpc-server.cpp"

# Routes matched directly in on_request, each with why it does not need to
# reach the dispatcher's budget. Adding a route means adding it here.
KNOWN_DIRECT_ROUTES = {
    "/healthcheck": "static reply, starts no work",
    "/api-info": "static literal, starts no work",
    "/readyz": "bounded by its own short-lived answer cache, not by budget",
}

# Routes that must be seen applying the budget themselves.
#
# /readyz deliberately is not one of them: refusing a probe forces a wrong
# answer either way -- "ready" keeps traffic on a node that may be out of
# sync, "not ready" pulls a healthy one out of rotation -- so its cost is
# bounded by caching the answer instead. A route that starts work and can
# afford to be refused belongs here.
MUST_GATE = set()

# Routes bounded some other way, each with the mechanism named. A route
# here must not simply be unbounded.
# The marker is the assignment that arms the bound, not the name: a
# declaration and a read survive deleting the mechanism, so matching
# the name alone would keep passing after the bound is gone.
MUST_BOUND_OTHERWISE = {"/readyz": "readyz_cached_until_ = td::Timestamp::in("}


def check_no_raw_this_captures() -> int:
    """No lambda in the JSON-RPC surface may capture a bare `this`.

    These lambdas become promises handed to other actors, and such a
    promise outlives this one: an abandoned promise is still invoked, and
    a reply can arrive after the server has stopped. Single-threaded
    execution rules out a data race, not a destroyed object. The safe
    forms are an actor id plus a hop back, or a shared owner for whatever
    the callback actually needs.
    """
    # A bare `this` token inside a lambda capture list, wherever it sits:
    # `[this`, `[x, this]`, `[a = b, this, c]`. The earlier check keyed on
    # the literal `[this` and so missed `this` in any position but the
    # first -- which let a real raw capture through. The safe idiom
    # `actor_id(this)` has `this` inside parentheses, not as a capture, so
    # it is excluded by requiring the token to be bounded by a capture-list
    # separator (`[`, `,`) and a terminator (`,`, `]`, `=`).
    capture_this = re.compile(r"\[[^\]]*(?:\[|,|\s)this\s*(?:,|\]|=)")
    offenders = []
    for path in sorted(SERVER.parent.glob("json-rpc-server*.cpp")):
        for number, line in enumerate(path.read_text().splitlines(), 1):
            # `[this` at the very start of a capture list, or `this` after a
            # separator; either way not `actor_id(this)` (a `(` precedes it).
            if re.search(r"\[\s*this\s*(?:,|\]|=)", line) or capture_this.search(line):
                offenders.append(f"{path.name}:{number}: {line.strip()}")
    if offenders:
        print("FAIL: lambda(s) capturing a bare `this`:")
        for offender in offenders:
            print(f"  {offender}")
        print()
        print("Capture actor_id(this) and hop back with send_closure, or capture a")
        print("shared owner of the state the callback needs.")
        return 1
    return 0


def main() -> int:
    source = SERVER.read_text()

    if check_no_raw_this_captures() != 0:
        return 1

    found = set(re.findall(r'url == "(/[a-zA-Z0-9_-]+)"', source))
    unknown = found - set(KNOWN_DIRECT_ROUTES)
    if unknown:
        print("FAIL: route(s) handled in on_request that this check does not know about:")
        for route in sorted(unknown):
            print(f"  {route}")
        print()
        print("Each direct route either starts work -- a liteserver query, a scan,")
        print("a VM run -- and must call consume_per_ip_token first, or is a static")
        print("reply that starts none. Decide which, then add it to")
        print("KNOWN_DIRECT_ROUTES (and to MUST_GATE if it starts work).")
        return 1

    missing = set(KNOWN_DIRECT_ROUTES) - found
    if missing:
        print("FAIL: route(s) listed here but no longer present in the source:")
        for route in sorted(missing):
            print(f"  {route}")
        print("Remove them from KNOWN_DIRECT_ROUTES so this check keeps its meaning.")
        return 1

    for route, marker in sorted(MUST_BOUND_OTHERWISE.items()):
        if marker not in source and marker not in (SERVER.parent / "json-rpc-server-utils.cpp").read_text():
            print(f"FAIL: {route} is recorded as bounded by {marker}, which no longer exists.")
            print("Either restore that bound or move the route into MUST_GATE.")
            return 1

    for route in sorted(MUST_GATE):
        # The gate has to appear between this route's match and its handler.
        match = re.search(
            r'url == "%s".*?\n(.*?)\n\s*return;' % re.escape(route),
            source,
            re.DOTALL,
        )
        if match is None:
            print(f"FAIL: could not locate the handler body for {route}")
            return 1
        if "consume_per_ip_token" not in match.group(1):
            print(f"FAIL: {route} starts work but does not consume the per-source budget.")
            print("It bypasses cached_dispatch_method, so the budget has to be applied here.")
            return 1

    print(f"OK: {len(found)} direct route(s) accounted for, "
          f"{len(MUST_GATE)} gated, {len(MUST_BOUND_OTHERWISE)} bounded otherwise.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
