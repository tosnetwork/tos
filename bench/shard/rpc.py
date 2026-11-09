"""A JSON-RPC client paced inside a share of a node's per-source request budget.

Every validator's JSON-RPC gate admits a fixed number of requests per window
from one source address (600 per 10 s by default), and loopback tunnels are
not exempt. Monitoring and handover checks share that budget, so a bench
reader takes only a configured share of it. Every request counts against the
share, retries included, and a reply that says the gate refused the request
(HTTP 429, or the JSON-RPC error -32005) is retried after a backoff rather
than reported as a chain answer.
"""

import asyncio
import json
import math
import time
import urllib.error
import urllib.request
from collections import deque
from collections.abc import Awaitable, Callable
from typing import Any

PER_IP_REQUESTS = 600
PER_IP_WINDOW = 10.0
RATE_LIMITED_CODE = -32005

# (url, body, timeout) -> (HTTP status, response body)
Transport = Callable[[str, bytes, float], Awaitable[tuple[int, bytes]]]


class RpcError(Exception):
    """The node answered, and the answer is an error that a retry does not change."""

    def __init__(self, method: str, status: int, error: Any):
        super().__init__(f"{method}: HTTP {status}: {error}")
        self.method, self.status, self.error = method, status, error


class RateLimited(Exception):
    """Every attempt was refused by the node's rate gate."""


class Budget:
    """At most ``requests`` request starts in any ``window`` seconds (a sliding window)."""

    def __init__(self, requests: int, window: float, clock: Callable[[], float] = time.monotonic):
        if type(requests) is not int or requests < 1:
            raise ValueError("a budget admits at least one request")
        if not window > 0:
            raise ValueError("a budget window must be positive")
        self.requests, self.window, self.clock = requests, window, clock
        self._starts: deque[float] = deque()

    def delay(self) -> float:
        """Seconds until one more request fits; 0 when it fits now."""
        now = self.clock()
        while self._starts and self._starts[0] <= now - self.window:
            self._starts.popleft()
        if len(self._starts) < self.requests:
            return 0.0
        return self._starts[0] + self.window - now

    def take(self) -> None:
        self._starts.append(self.clock())


async def urllib_transport(url: str, body: bytes, timeout: float) -> tuple[int, bytes]:
    request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})

    def post() -> tuple[int, bytes]:
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            with error:
                return error.code, error.read()

    return await asyncio.to_thread(post)


class PacedRpc:
    """One JSON-RPC endpoint, read inside ``share`` of its per-source budget."""

    def __init__(
        self,
        url: str,
        share: float = 0.25,
        *,
        requests: int = PER_IP_REQUESTS,
        window: float = PER_IP_WINDOW,
        attempts: int = 6,
        backoff: float = 0.5,
        timeout: float = 10.0,
        transport: Transport = urllib_transport,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        if not 0 < share <= 1:
            raise ValueError("the budget share must be in (0, 1]")
        if type(attempts) is not int or attempts < 1:
            raise ValueError("a call needs at least one attempt")
        limit = math.floor(requests * share)
        if limit < 1:
            raise ValueError("the share leaves no request in the budget")
        self.url, self.share, self.attempts, self.backoff = url, share, attempts, backoff
        self.timeout, self.transport, self.sleep = timeout, transport, sleep
        self.budget = Budget(limit, window, clock)
        self._lock = asyncio.Lock()
        self._id = 0
        self.sent = 0
        self.throttled = 0

    async def _slot(self) -> None:
        async with self._lock:
            while (wait := self.budget.delay()) > 0:
                await self.sleep(wait)
            self.budget.take()
            self.sent += 1

    async def call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        """The method's ``result``; raises RpcError on an error answer, RateLimited when refused."""
        for attempt in range(self.attempts):
            self._id += 1
            body = json.dumps(
                {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}}
            ).encode()
            await self._slot()
            status, raw = await self.transport(self.url, body, self.timeout)
            try:
                document = json.loads(raw) if raw else {}
            except ValueError:
                document = {}
            if not isinstance(document, dict):
                document = {}
            error = document.get("error")
            refused = status == 429 or (
                isinstance(error, dict) and error.get("code") == RATE_LIMITED_CODE
            )
            if refused:
                self.throttled += 1
                if attempt + 1 < self.attempts:
                    await self.sleep(min(self.budget.window, self.backoff * 2**attempt))
                continue
            if status != 200 or error is not None or "result" not in document:
                raise RpcError(method, status, error if error is not None else raw[:200])
            return document["result"]
        raise RateLimited(f"{method}: refused by the rate gate {self.attempts} times")

    def stats(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "share": self.share,
            "budget_requests": self.budget.requests,
            "budget_window": self.budget.window,
            "sent": self.sent,
            "throttled": self.throttled,
        }
