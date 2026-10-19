#!/usr/bin/env bash
# Run the local CI replay with its one dependency (PyYAML) supplied by uv.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec uv run --no-project --quiet --python 3.12 --with 'pyyaml==6.0.3' \
  python "$here/local_ci.py" "$@"
