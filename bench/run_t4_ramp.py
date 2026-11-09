#!/usr/bin/env python3
"""T4 transfer ramp against existing JSON-RPC endpoints (bench/t4/ramp.py).

The ramp reads and sends over JSON-RPC only, so nothing here imports a
liteserver or local-net module. Run with ``--help`` for its options.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "bench"), str(ROOT / "test/tostester/src")]

from t4 import ramp  # noqa: E402

if __name__ == "__main__":
    sys.exit(ramp.main(sys.argv[1:]))
