#!/usr/bin/env python3
"""
stratum-adapter.py — TOS JSON-RPC to Stratum v1 bridge for eTOS mining.

This script listens for incoming stratum v1 connections from GPU miners
(ethminer, T-Rex, lolMiner, etc.) and bridges their job/submit messages
to the eTOS PoW Giver contract via the TOS node's JSON-RPC interface.

Usage:
    python3 stratum-adapter.py \\
        --rpc http://YOUR_TOS_NODE_IP:8081 \\
        --listen 0.0.0.0:4444

Dependencies:
    pip install requests

Status: v1 stub — core scaffolding is in place; the RPC polling loop
and full stratum message dispatch are marked TODO below.  The interface
and configuration surface are stable; implementation will be completed
in a future release.

Design reference:
    doc/Mining-Design.md §eTOS Mining
    evm/contracts/etos-miner-config/README.md
"""

import argparse
import asyncio
import json
import logging
import sys
from typing import Optional

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------

DEFAULT_RPC_URL = "http://127.0.0.1:8081"
DEFAULT_LISTEN_HOST = "0.0.0.0"
DEFAULT_LISTEN_PORT = 4444
DEFAULT_POLL_INTERVAL = 2.0  # seconds; eTOS target_delta = 12s

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("stratum-adapter")


# ---------------------------------------------------------------------------
# TOS RPC client (minimal)
# ---------------------------------------------------------------------------

class TosRpcClient:
    """Thin wrapper around the TOS node's eth_* JSON-RPC namespace."""

    def __init__(self, rpc_url: str) -> None:
        self.rpc_url = rpc_url
        self._id = 0

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def call(self, method: str, params=None):
        """
        Synchronous JSON-RPC call.

        TODO: replace with async httpx/aiohttp for production use.
        """
        import urllib.request
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
            "params": params or [],
        }).encode()
        req = urllib.request.Request(
            self.rpc_url,
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = json.loads(resp.read())
        if "error" in body:
            raise RuntimeError(f"RPC error: {body['error']}")
        return body.get("result")

    def get_work(self):
        """
        Fetch current PoW work from the eTOS Giver contract.

        Returns a tuple (seed_hash, target, block_number) matching the
        eth_getWork stratum convention:
          [0] = current block / seed hash (32-byte hex)
          [1] = target boundary (32-byte hex, inverted difficulty)
          [2] = block number (hex)

        TODO: implement the eTOSPoWGiver.sol query.
        The Giver exposes `seed` (bytes16) and `target` (uint256);
        map these to eth_getWork format expected by stratum clients.
        """
        # TODO: query EToSPoWGiver.seed and EToSPoWGiver.target via eth_call
        raise NotImplementedError("get_work: TODO implement eTOSPoWGiver query")

    def submit_work(self, nonce: str, pow_hash: str, mix_digest: str) -> bool:
        """
        Submit a solved nonce to the eTOS Giver contract.

        TODO: encode and broadcast an eth_sendRawTransaction calling
        EToSPoWGiver.mine(nonce, recipient, expire, rseed, rdata1, rdata2).
        """
        # TODO: build and sign the mine() transaction
        raise NotImplementedError("submit_work: TODO implement mine() transaction")


# ---------------------------------------------------------------------------
# Stratum v1 session handler
# ---------------------------------------------------------------------------

class StratumSession:
    """
    Handles one stratum v1 TCP connection from a GPU miner.

    Protocol reference: https://en.bitcoin.it/wiki/Stratum_mining_protocol
    (Ethereum stratum variant used by ethminer / T-Rex)
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        rpc: TosRpcClient,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.rpc = rpc
        self.peer = writer.get_extra_info("peername")
        self.subscribed = False
        self.authorized = False
        self.worker: Optional[str] = None

    async def run(self) -> None:
        log.info("New miner connection from %s", self.peer)
        try:
            while True:
                line = await self.reader.readline()
                if not line:
                    break
                await self._handle_message(line.decode().strip())
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            log.info("Miner disconnected: %s", self.peer)
            self.writer.close()

    async def _handle_message(self, raw: str) -> None:
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            log.warning("Malformed message from %s: %s", self.peer, raw[:200])
            return

        method = msg.get("method", "")
        msg_id = msg.get("id")

        if method == "mining.subscribe":
            await self._on_subscribe(msg_id)
        elif method == "mining.authorize":
            await self._on_authorize(msg_id, msg.get("params", []))
        elif method == "mining.submit":
            await self._on_submit(msg_id, msg.get("params", []))
        else:
            log.debug("Unknown method from %s: %s", self.peer, method)

    async def _on_subscribe(self, msg_id) -> None:
        # TODO: respond with proper subscription IDs and extranonce
        response = {
            "id": msg_id,
            "result": [
                [["mining.notify", "etos-adapter-v1"]],
                "00000000",  # extranonce1 (placeholder)
                4,           # extranonce2 size
            ],
            "error": None,
        }
        await self._send(response)
        self.subscribed = True

    async def _on_authorize(self, msg_id, params) -> None:
        worker = params[0] if params else "unknown"
        self.worker = worker
        self.authorized = True
        log.info("Worker authorized: %s (peer=%s)", worker, self.peer)
        response = {"id": msg_id, "result": True, "error": None}
        await self._send(response)
        # TODO: immediately send a mining.notify with current work

    async def _on_submit(self, msg_id, params) -> None:
        # params: [worker_name, job_id, extranonce2, ntime, nonce]
        log.info("Share submitted by %s: %s", self.worker, params)
        # TODO: validate and relay to TosRpcClient.submit_work()
        response = {"id": msg_id, "result": True, "error": None}
        await self._send(response)

    async def _send(self, obj) -> None:
        data = (json.dumps(obj) + "\n").encode()
        self.writer.write(data)
        await self.writer.drain()


# ---------------------------------------------------------------------------
# Work notification broadcaster
# ---------------------------------------------------------------------------

class WorkBroadcaster:
    """
    Polls the TOS node for new PoW work and notifies connected miners.

    TODO: implement full polling + mining.notify dispatch.
    """

    def __init__(self, rpc: TosRpcClient, sessions: list, interval: float) -> None:
        self.rpc = rpc
        self.sessions = sessions
        self.interval = interval

    async def run(self) -> None:
        while True:
            await asyncio.sleep(self.interval)
            # TODO: call self.rpc.get_work() and broadcast mining.notify
            #       to all authorized sessions in self.sessions.


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def main(rpc_url: str, host: str, port: int) -> None:
    rpc = TosRpcClient(rpc_url)
    sessions: list = []

    async def handle_client(reader, writer):
        sess = StratumSession(reader, writer, rpc)
        sessions.append(sess)
        try:
            await sess.run()
        finally:
            sessions.remove(sess)

    server = await asyncio.start_server(handle_client, host, port)
    broadcaster = WorkBroadcaster(rpc, sessions, DEFAULT_POLL_INTERVAL)

    log.info("eTOS stratum adapter listening on %s:%d", host, port)
    log.info("TOS RPC endpoint: %s", rpc_url)
    log.warning(
        "This is a v1 stub. Work polling and share submission are not yet "
        "implemented. See stratum-adapter.py TODOs."
    )

    async with server:
        await asyncio.gather(
            server.serve_forever(),
            broadcaster.run(),
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="TOS JSON-RPC to Stratum v1 bridge for eTOS mining",
    )
    parser.add_argument(
        "--rpc",
        default=DEFAULT_RPC_URL,
        metavar="URL",
        help=f"TOS node JSON-RPC endpoint (default: {DEFAULT_RPC_URL})",
    )
    parser.add_argument(
        "--listen",
        default=f"{DEFAULT_LISTEN_HOST}:{DEFAULT_LISTEN_PORT}",
        metavar="HOST:PORT",
        help=f"Stratum listen address (default: {DEFAULT_LISTEN_HOST}:{DEFAULT_LISTEN_PORT})",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    try:
        host, port_str = args.listen.rsplit(":", 1)
        port = int(port_str)
    except ValueError:
        print(f"ERROR: --listen must be HOST:PORT, got: {args.listen}", file=sys.stderr)
        sys.exit(1)

    try:
        asyncio.run(main(rpc_url=args.rpc, host=host, port=port))
    except KeyboardInterrupt:
        log.info("Adapter stopped.")
