#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
python_version="$(tr -d '[:space:]' < "$root/.python-version")"
if [[ ! -x "$root/.contract-venv/bin/python" ]]; then
  uv venv --python "$python_version" "$root/.contract-venv"
fi
actual="$($root/.contract-venv/bin/python -c 'import platform; print(platform.python_version())')"
if [[ "$actual" != "$python_version" ]]; then
  echo "contract Python mismatch: expected $python_version, got $actual" >&2
  exit 1
fi
uv pip install --python "$root/.contract-venv/bin/python" --require-hashes \
  -r "$root/requirements-contracts.lock"
