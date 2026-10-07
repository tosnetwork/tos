"""Private directories for the tosctl configuration and vault of e2e runs.

tosctl writes its configuration and file vault only into a directory that no
other user can modify, including every ancestor directory. A checkout created
under umask 002 is group-writable, so a harness keeps these files in a fresh
private directory outside the checkout instead of next to its evidence.
"""

import os
import tempfile
from pathlib import Path

PARENT_ENV = "TOS_E2E_PRIVATE_DIR"


def make_private_dir(harness: str) -> Path:
    """Create a new mode-0700 directory for one run of `harness`.

    TOS_E2E_PRIVATE_DIR names the parent to create it in (default: the
    system temporary directory). Nothing that already exists is reused or
    removed; the directory is kept after the run for inspection.
    """
    parent = os.environ.get(PARENT_ENV) or None
    path = Path(tempfile.mkdtemp(prefix=f"tos-{harness}-", dir=parent))
    print(f"tosctl configuration and vault for this run: {path}")
    return path
