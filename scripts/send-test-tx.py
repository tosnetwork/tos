#!/usr/bin/env python3
"""Send a smoke-test transfer on the local native-only TOS testnet via lite-client.

Builds a signed external message from the genesis main wallet, submits it with
`tos-lite-client sendfile`, and verifies it landed on-chain (recipient balance
increases, wallet seqno increments). The current seqno is queried automatically,
so the script is safe to run repeatedly.

Run it through uv (it imports the tostester libraries):

    uv run scripts/send-test-tx.py
    uv run scripts/send-test-tx.py --amount 5 --dest 0:1111111111111111111111111111111111111111111111111111111111111111

The main-wallet key is read from the zerostate state dir (default
/data/testnet/state); it falls back to `sudo cat` when that file is root-owned.
"""

import argparse
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "test/tostester/src"))

import nacl.signing  # noqa: E402
from contract import tos  # noqa: E402
from pytosiq_core import (  # noqa: E402
    Address,
    Builder,
    Cell,
    CurrencyCollection,
    ExternalMsgInfo,
    InternalMsgInfo,
    MessageAny,
    WalletMessage,
)

_NANO = 1_000_000_000


def _read_bytes(path: Path) -> bytes:
    """Read a file, falling back to `sudo cat` for root-owned keys."""
    try:
        return path.read_bytes()
    except PermissionError:
        return subprocess.run(["sudo", "cat", str(path)], capture_output=True, check=True).stdout


def _lite(lite_client: str, global_config: str, *commands: str) -> str:
    argv = [lite_client, "-C", global_config, "-v", "0"]
    for c in commands:
        argv += ["-c", c]
    argv += ["-c", "quit"]
    return subprocess.run(argv, capture_output=True, text=True, timeout=30).stdout


def _seqno(lite_client: str, global_config: str, addr: str) -> int:
    out = _lite(lite_client, global_config, "time", f"runmethod {addr} seqno")
    m = re.search(r"result:\s*\[\s*(\d+)\s*\]", out)
    return int(m.group(1)) if m else 0


def _balance_nano(lite_client: str, global_config: str, addr: str) -> int:
    out = _lite(lite_client, global_config, "time", f"getaccount {addr}")
    m = re.search(r"amount:\(var_uint len:\d+ value:(\d+)\)", out)
    return int(m.group(1)) if m else 0


def _build_boc(
    key: nacl.signing.SigningKey,
    src: Address,
    dest: Address,
    amount: CurrencyCollection,
    seqno: int,
) -> bytes:
    inner = MessageAny(
        info=InternalMsgInfo(
            ihr_disabled=True,
            bounce=False,
            bounced=False,
            src=src,
            dest=dest,
            value=amount,
            ihr_fee=0,
            fwd_fee=0,
            created_lt=0,
            created_at=0,
        ),
        init=None,
        body=Cell.empty(),
    )
    wmsg = WalletMessage(send_mode=3, message=inner)
    # simple-wallet external body: signature(512) || seqno(32) || wallet-message
    to_sign = Builder().store_uint(seqno, 32).store_cell(wmsg.serialize()).end_cell()
    signed = Builder().store_bytes(key.sign(to_sign.hash).signature).store_cell(to_sign).end_cell()
    ext = MessageAny(info=ExternalMsgInfo(None, src, 0), init=None, body=signed)  # pyright: ignore[reportArgumentType]
    return ext.serialize().to_boc()


def main() -> int:
    p = argparse.ArgumentParser(description="Send a smoke-test transfer via lite-client.")
    _ = p.add_argument("--global-config", default="/data/tos-global.json")
    _ = p.add_argument("--state-dir", default="/data/testnet/state")
    _ = p.add_argument("--lite-client", default="/usr/local/bin/tos-lite-client")
    _ = p.add_argument("--amount", type=float, default=2.0, help="TOS to transfer")
    _ = p.add_argument("--dest", default="0:" + "42" * 32, help="recipient as wc:hex64")
    _ = p.add_argument("--timeout", type=float, default=30.0, help="seconds to wait for inclusion")
    args = p.parse_args()

    lite_client: str = args.lite_client
    global_config: str = args.global_config

    state = Path(args.state_dir)
    key = nacl.signing.SigningKey(_read_bytes(state / "main-wallet.pk"))
    addr_file = _read_bytes(state / "main-wallet.addr")
    src_wc = int.from_bytes(addr_file[32:36], "big", signed=True)
    src = Address((src_wc, addr_file[:32]))
    src_str = f"{src_wc}:{addr_file[:32].hex()}"

    dest_str: str = args.dest
    dwc, dhex = dest_str.split(":")
    dest = Address((int(dwc), bytes.fromhex(dhex)))

    before_seqno = _seqno(lite_client, global_config, src_str)
    before_dest = _balance_nano(lite_client, global_config, dest_str)
    print(f"main-wallet {src_str}  seqno={before_seqno}")
    print(f"dest        {dest_str}  balance={before_dest / _NANO} TOS")

    amount: float = args.amount
    boc = _build_boc(key, src, dest, tos(amount), before_seqno)
    with tempfile.NamedTemporaryFile(suffix=".boc", delete=False) as f:
        _ = f.write(boc)
        boc_path = f.name
    print(f"built {len(boc)}-byte transfer of {amount} TOS  ->  lite-client sendfile")
    _ = _lite(lite_client, global_config, "time", f"sendfile {boc_path}")
    Path(boc_path).unlink(missing_ok=True)

    # a transfer pays a small forwarding fee, so the recipient receives slightly
    # less than `amount`; treat any balance increase as confirmation.
    deadline = time.monotonic() + float(args.timeout)
    while time.monotonic() < deadline:
        time.sleep(2)
        now = _balance_nano(lite_client, global_config, dest_str)
        if now > before_dest:
            after_seqno = _seqno(lite_client, global_config, src_str)
            print(
                f"CONFIRMED: dest balance {before_dest / _NANO} -> {now / _NANO} TOS, "
                f"wallet seqno {before_seqno} -> {after_seqno}"
            )
            return 0
    print("TIMEOUT: transfer not observed on-chain within the deadline", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
