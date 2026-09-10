#!/usr/bin/env python3
"""Guard actual default-OFF validator decisions, retaining prepared controls.

The old unconditional-source-pattern check could not distinguish D59 test-only
permission from production enablement. The required probe now executes both
actual production decision functions. LIMIT: this detects default behavior
changing, not correctness of test-enabled execution or full actor reachability.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--probe', type=Path, required=True)
    p.add_argument('--fixture', type=Path, required=True)
    a = p.parse_args()
    try:
        result = subprocess.run([str(a.probe), str(a.fixture)])
    except OSError as error:
        print(json.dumps({'failure_identity': 1352, 'detail': str(error)}), file=sys.stderr)
        return 1
    if result.returncode != 0:
        print(json.dumps({'action': 'Restore default-OFF behavior and both LocalUnavailable refusals. '
                          'D59 test-only execution does not authorize production enablement; '
                          'retain prepared controls until a separate production gate decision.'}), file=sys.stderr)
        return 1
    print('Default behavior guard passed: OFF; both actual validator decisions refuse.', flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
