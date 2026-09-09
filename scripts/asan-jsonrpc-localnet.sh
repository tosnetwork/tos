#!/usr/bin/env bash
# Bring up a local chain whose nodes are AddressSanitizer-instrumented,
# serving JSON-RPC on 127.0.0.1:18545, so a request corpus can be driven
# against a real HTTP -> parser -> actor -> callback path.
#
# Two things here are not obvious and each one costs an afternoon to
# rediscover:
#
#   - toslib is loaded into python with ctypes. Python is not
#     instrumented, so the sanitizer runtime is not in that process and
#     the instrumented library fails to resolve its symbols. Preloading
#     the runtime fixes the import.
#
#   - that same preload must not reach the node processes. They link
#     their own copy of the runtime, and a second one arriving through
#     the environment aborts them immediately with "linked against
#     incompatible ASan runtimes" -- which surfaces as an unexplained
#     non-zero exit from a helper binary that runs fine by hand.
#
# So: preload, load the library, then drop the variable before anything
# is spawned.
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

BUILD_DIR=${TOS_BUILD_DIR:-"$REPO_ROOT/build-asan"}
VALIDATORS=${VALIDATORS:-1}

# The harness needs the tostester dependencies, so a bare system python
# will not do. Prefer an interpreter that already has them.
if [[ -z "${PYTHON:-}" ]]; then
  if [[ -x "$REPO_ROOT/.venv/bin/python" ]]; then
    PYTHON="$REPO_ROOT/.venv/bin/python"
  else
    PYTHON=python3
  fi
fi

export TOS_BUILD_DIR="$BUILD_DIR"
export PYTHONPATH="$REPO_ROOT/test/tostester/src${PYTHONPATH:+:$PYTHONPATH}"
export ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=0:halt_on_error=0}
# Reports go to files so the harness can tell "nothing happened" from
# "something happened and scrolled past".
export ASAN_OPTIONS="${ASAN_OPTIONS}:log_path=/tmp/asan-report:detect_stack_use_after_return=0"

if [[ ! -x "$BUILD_DIR/validator-engine/validator-engine" ]]; then
  echo "instrumented node not found: $BUILD_DIR/validator-engine/validator-engine" >&2
  exit 1
fi

ASAN_RUNTIME=${ASAN_RUNTIME:-}
if [[ -z "$ASAN_RUNTIME" ]]; then
  for candidate in clang-21 clang; do
    if command -v "$candidate" > /dev/null; then
      ASAN_RUNTIME=$("$candidate" -print-file-name=libclang_rt.asan-x86_64.so 2>/dev/null || true)
      [[ -f "$ASAN_RUNTIME" ]] && break
      ASAN_RUNTIME=""
    fi
  done
fi
if [[ ! -f "$ASAN_RUNTIME" ]]; then
  echo "could not locate the AddressSanitizer runtime; set ASAN_RUNTIME" >&2
  exit 1
fi

export LD_PRELOAD="$ASAN_RUNTIME"
exec "$PYTHON" -c "
import ctypes, os, runpy, sys

# Resolve the instrumented library while the runtime is still preloaded.
ctypes.CDLL(os.path.join(os.environ['TOS_BUILD_DIR'], 'toslib', 'libtoslibjson.so'),
            mode=ctypes.RTLD_GLOBAL)

# Everything spawned from here links its own runtime; a second copy is fatal.
os.environ.pop('LD_PRELOAD', None)

sys.argv = ['scripts/localnet-jsonrpc.py', '--validators', '${VALIDATORS}']
runpy.run_path('scripts/localnet-jsonrpc.py', run_name='__main__')
"
