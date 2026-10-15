#!/usr/bin/env bash
# Run one-time Linux state-import evidence in a disposable checkout.
# Usage: validate-state-import.sh PHASE HEAD_BUILD BASE_BUILD RECEIPTS CODECHECKER
# PHASE is native, prepare, analyze, or sensitivity. Ordinary PR CI does not
# invoke this runner. The sensitivity phase temporarily changes tracked sources;
# it refuses dirty inputs and restores their original bytes before rebuilding.
set -euo pipefail

validation_phase="${1:?phase required}"
validation_build="$(realpath "${2:?HEAD build required}")"
validation_base="$(realpath "${3:?BASE build required}")"
mkdir -p "${4:?receipt directory required}"
validation_receipts="$(realpath "$4")"
validation_codechecker="${5:?CodeChecker required}"
validation_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
validation_jobs="${STATE_VALIDATION_JOBS:-2}"
cd "$validation_root"

if [ "$(uname -s)" != Linux ]; then
  echo 'This evidence runner requires Linux.' >&2
  exit 2
fi

python3 - "$validation_root" "$validation_build" <<'PY'
from pathlib import Path
import re
import sys

cache = (Path(sys.argv[2]) / 'CMakeCache.txt').read_text()
home = re.search(r'^CMAKE_HOME_DIRECTORY:INTERNAL=(.*)$', cache, re.M)
if home is None or Path(home.group(1)).resolve() != Path(sys.argv[1]).resolve():
    raise SystemExit('HEAD build does not belong to this checkout')
PY

case "$validation_phase" in
  native)
    cmake --build "$validation_build" --target test-state-download-recovery \
      test-download-state-budget test-celldb-streaming-import -j"$validation_jobs" \
      2>&1 | tee "$validation_receipts/build.log"
    printf '%s\n' streaming-boc-cell-bounds streaming-boc-valid-ondisk \
      test-state-download-recovery test-celldb-streaming-import > "$validation_receipts/import-inventory.txt"
    python3 scripts/check-ctest-inventory.py --build-dir "$validation_build" \
      --expected-file "$validation_receipts/import-inventory.txt"
    ctest --test-dir "$validation_build" --output-on-failure --no-tests=error \
      -R '^streaming-boc-|^test-celldb-streaming-import$' 2>&1 | tee "$validation_receipts/import-tests.log"
    TOS_FAST_TESTS=1 "$validation_build/test-download-state-budget" \
      2>&1 | tee "$validation_receipts/budget-tests.log"
    sudo unshare --net bash -c 'ip link set lo up; exec "$@"' test \
      "$validation_build/test-state-download-recovery" test/pq-native/data/c04-pq-genesis.boc \
      2>&1 | tee "$validation_receipts/recovery.log"
    ;;
  prepare)
    python3 - "$validation_build" "$validation_base" "$validation_jobs" <<'PY' \
      2>&1 | tee "$validation_receipts/generated.log"
from pathlib import Path
import os
import subprocess
import sys

for directory in sys.argv[1:3]:
    rows = subprocess.check_output(['ninja', '-C', directory, '-t', 'targets', 'all'], text=True)
    targets = [line.rsplit(': ', 1)[0] for line in rows.splitlines()
               if Path(line.rsplit(': ', 1)[0]).suffix in {'.h', '.hpp', '.hh', '.cpp', '.cc', '.c', '.inc'}]
    if not targets:
        raise RuntimeError('no generated targets found')
    source = str(Path(directory).parent)
    env = dict(os.environ, CCACHE_BASEDIR=source,
               TOL_STDLIB=str(Path(source) / 'crypto/smartcont/tol-stdlib'))
    print(directory, 'generated targets:', len(targets), flush=True)
    # MHD exports its header as a side effect of its library target. Scanning
    # the complete configured database includes the explorer even when native
    # state-import targets alone did not need this library.
    subprocess.run(['ninja', '-C', directory, '-j' + sys.argv[3], 'mhd', *targets], check=True, env=env)
    if not (Path(directory) / 'third-party/libmicrohttpd/include/microhttpd.h').is_file():
        raise RuntimeError('configured explorer dependency was not prepared')
PY
    ;;
  analyze)
    python3 -u scripts/static-analysis.py --build-dir "$validation_build" \
      --base-build-dir "$validation_base" --codechecker "$validation_codechecker" \
      --jobs "$validation_jobs" 2>&1 | tee "$validation_receipts/static-analysis.log"
    ;;
  sensitivity)
    python3 - "$validation_root" "$validation_build" "$validation_receipts" "$validation_jobs" <<'PY' \
      2>&1 | tee "$validation_receipts/sensitivity.log"
from pathlib import Path
import hashlib
import json
import subprocess
import sys

repo, build, receipts = map(Path, sys.argv[1:4])
jobs = sys.argv[4]

def remove_import_cleanup(text):
    begin = text.index('void DownloadShardState::on_streaming_import_done(')
    end = text.index('  auto result = r_result.move_as_ok();', begin)
    branch = text[begin:end]
    for line in ['    data_file_ = fullnode::BudgetedStateFile{};\n',
                 '    data_reservation_.reset();\n', '    state_processing_reservation_.reset();\n']:
        if branch.count(line) != 1:
            raise RuntimeError('import cleanup control no longer matches')
        branch = branch.replace(line, '')
    return text[:begin] + branch + text[end:]

def remove_download_cleanup(text):
    begin = text.index('void DownloadState::abort_query(')
    end = text.index('void DownloadState::alarm()', begin)
    branch = text[begin:end]
    if branch.count('  cleanup_tempfile();\n') != 1:
        raise RuntimeError('download cleanup control no longer matches')
    return text[:begin] + branch.replace('  cleanup_tempfile();\n', '') + text[end:]

def remove_handoff(text):
    line = '    worker_done->store(true, std::memory_order_release);\n'
    if text.count(line) != 1:
        raise RuntimeError('worker handoff control no longer matches')
    # Retain the capture's use under -Werror while withholding publication.
    return text.replace(line, '    worker_done->store(false, std::memory_order_release);\n')

cases = [
    ('root', 'validator/downloaders/download-state.cpp', remove_import_cleanup, '--root-recovery',
     'STATE_DOWNLOAD_RECOVERY_FAILURE: download reservation leaked'),
    ('download', 'validator/net/download-state.cpp', remove_download_cleanup, '--download-recovery',
     'STATE_DOWNLOAD_RECOVERY_FAILURE: failed import/download left temporary resources'),
    ('handoff', 'validator/db/celldb.cpp', remove_handoff, '--download-recovery',
     'STATE_DOWNLOAD_RECOVERY_FAILURE: deadline: source recovery'),
]
paths = [entry[1] for entry in cases]
if subprocess.check_output(['git', 'status', '--porcelain', '--', *paths], cwd=repo, text=True).strip():
    raise RuntimeError('sensitivity inputs must be clean tracked sources')
originals = {name: (repo / name).read_bytes() for name in paths}
results = []

def rebuild(name):
    with (receipts / (name + '-build.log')).open('w') as log:
        subprocess.run(['cmake', '--build', str(build), '--target', 'test-state-download-recovery', '-j' + jobs],
                       cwd=repo, stdout=log, stderr=subprocess.STDOUT, check=True)

try:
    for name, path, mutate, selector, expected in cases:
        source = repo / path
        try:
            source.write_text(mutate(originals[path].decode()))
            rebuild(name + '-red')
            logpath = receipts / (name + '-red.log')
            with logpath.open('w') as log:
                result = subprocess.run(
                    ['sudo', 'unshare', '--net', 'bash', '-c', 'ip link set lo up; exec "$@"', 'test',
                     str(build / 'test-state-download-recovery'),
                     'test/pq-native/data/c04-pq-genesis.boc', selector],
                    cwd=repo, stdout=log, stderr=subprocess.STDOUT, timeout=240)
            output = logpath.read_text()
            if result.returncode != 1 or expected not in output:
                raise RuntimeError(name + ' did not fail at the intended assertion: ' + output[-1500:])
            if name == 'handoff' and 'DELIVERY mode=OnDisk' not in output:
                raise RuntimeError('handoff control did not complete delivery')
            row = dict(control=name, exit=result.returncode, assertion=expected,
                       source_sha256=hashlib.sha256(originals[path]).hexdigest(),
                       log_sha256=hashlib.sha256(logpath.read_bytes()).hexdigest())
            results.append(row)
            print(json.dumps(row), flush=True)
        finally:
            source.write_bytes(originals[path])
finally:
    for path, original in originals.items():
        (repo / path).write_bytes(original)
    rebuild('restored')

if subprocess.check_output(['git', 'status', '--porcelain', '--', *paths], cwd=repo, text=True).strip():
    raise RuntimeError('sensitivity sources were not restored')
(receipts / 'sensitivity.json').write_text(json.dumps(results, indent=2) + '\n')
PY
    ;;
  *)
    echo "Unknown validation phase: $validation_phase" >&2
    exit 2
    ;;
esac
