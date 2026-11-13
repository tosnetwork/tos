# Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
"""Put this directory on PYTHONPATH to record native emulator calls (see txnfam_capture.py)."""

import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
importlib.import_module("txnfam_capture").install()
