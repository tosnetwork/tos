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
    "/readyz": "gated: calls consume_per_ip_token before handle_readyz",
}

# Routes that must be seen applying the budget themselves.
MUST_GATE = {"/readyz"}


def main() -> int:
    source = SERVER.read_text()

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

    print(f"OK: {len(found)} direct route(s) accounted for, {len(MUST_GATE)} gated.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
