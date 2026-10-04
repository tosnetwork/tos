#!/usr/bin/env bash
# Install four PQ validators, two observers, a lite-client and a development shielded pool.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
BUILD="$REPO/build"
CLEAN=0
DO_BUILD=0
PLAN_ONLY=0
ROTATE=0
for arg in "$@"; do
    case "$arg" in
        --clean) CLEAN=1 ;;
        --build) DO_BUILD=1 ;;
        --plan-only) PLAN_ONLY=1 ;;
        --rotate) ROTATE=1 ;;
        *) echo "Usage: sudo $0 [--build] [--clean] [--plan-only] [--rotate]"; exit 2 ;;
    esac
done
[[ $EUID -eq 0 ]] || { echo 'Run with sudo'; exit 1; }
exec 9>/run/lock/tos-pq-setup.lock
flock -n 9 || { echo 'Another setup is running'; exit 1; }
if [[ $PLAN_ONLY == 1 ]]; then
    [[ $CLEAN == 0 && $DO_BUILD == 0 && $ROTATE == 0 ]] || { echo '--plan-only cannot build, clean, or enable rotation'; exit 2; }
    exec python3 "$REPO/scripts/local_pq_testnet.py" plan
fi
CALLER="${SUDO_USER:-root}"
CALLER_HOME="$(getent passwd "$CALLER" | cut -d: -f6)"
UV="$(command -v uv || true)"
[[ -n "$UV" ]] || UV="$CALLER_HOME/.local/bin/uv"
[[ -x "$UV" ]] || { echo 'uv is required'; exit 1; }
CARGO="$CALLER_HOME/.cargo/bin/cargo"
cd "$REPO"
if [[ $DO_BUILD == 1 ]]; then
    # Reserve 32 cores and 48 GiB before starting a cold native build.
    python3 - <<'CHECK'
import os, time
from pathlib import Path
m = dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
total = int(m['MemTotal'].split()[0]); available = int(m['MemAvailable'].split()[0])
def sample():
    return list(map(int, Path('/proc/stat').read_text().splitlines()[0].split()[1:9]))
a=sample(); time.sleep(1); b=sample(); d=[y-x for x,y in zip(a,b)]
busy=os.cpu_count()*(1-(d[3]+d[4])/max(1,sum(d)))
print(f'Build admission: CPU used {busy:.1f}/{os.cpu_count()}, memory available {available/1024**2:.1f} GiB')
if busy + 32 > os.cpu_count()*2/3 or total-available+48*1024**2 > total*2/3:
    raise SystemExit('Build resource budget unavailable; wait before rebuilding')
CHECK
    sudo -u "$CALLER" cmake -S . -B build -G Ninja -DCMAKE_C_COMPILER=clang-21 \
        -DCMAKE_CXX_COMPILER=clang++-21 -DCMAKE_BUILD_TYPE=Release -DTOS_ARCH=x86-64 \
        -DTOS_USE_JEMALLOC=ON -DTOS_PRODUCTION_BUILD=ON
    sudo -u "$CALLER" cmake --build build --parallel 32 --target gen_fif create-state \
        fift func toslibjson generate-random-id tos-pq-consensus-key dht-server \
        validator-engine-console validator-engine lite-client
    (cd tools/shielded-pool-circuit/crosscheck && sudo -u "$CALLER" "$CARGO" build \
        --release --locked -j2 --bin local_pool --bin local_pool_traffic)
fi
for binary in validator-engine/validator-engine dht-server/dht-server \
    validator-engine-console/validator-engine-console lite-client/lite-client \
    utils/generate-random-id crypto/pq/tos-pq-consensus-key crypto/create-state \
    crypto/fift crypto/func toslib/libtoslibjson.so; do
    [[ -f "$BUILD/$binary" ]] || { echo "Missing $BUILD/$binary; run --build"; exit 1; }
done
POOL_GENERATOR="$REPO/tools/shielded-pool-circuit/crosscheck/target/release/local_pool"
[[ -x "$POOL_GENERATOR" ]] || { echo 'Missing local_pool generator; run --build'; exit 1; }
# Finish preparation before touching the old data or services.
"$UV" run python test/tostester/generate_tl.py
STAGING="$(mktemp -d /var/tmp/tos-pq-pool.XXXXXX)"
trap 'rm -rf "$STAGING"' EXIT
TOS_ROOT="$REPO" "$POOL_GENERATOR" "$REPO" "$STAGING/pool"
"$UV" run python -c 'from pathlib import Path; import sys; from tostester.install import Install; from toslib import ToslibClient; Install(Path(sys.argv[1]), Path(sys.argv[2])).toslibjson' "$BUILD" "$REPO"
[[ ! -L /data ]] || { echo '/data must not be a symlink'; exit 1; }
if [[ -d /data ]] && [[ -n "$(find /data -mindepth 1 -maxdepth 1 -print -quit)" ]] && [[ $CLEAN != 1 ]]; then
    echo '/data contains an existing network. Use --clean to replace all of its data.'; exit 1
fi
for unit in tos-pq-privacy tos-pq-transfers tos-pq-elections tos-pq-lite-client tos-pq-observer@5 tos-pq-observer@6 tos-dht tos-pq-dht; do systemctl disable --now "$unit" 2>/dev/null || true; done
for i in $(seq 1 20); do
    for prefix in tos-validator tos-pq-validator; do
        systemctl stop "$prefix@$i" 2>/dev/null || true
        systemctl disable "$prefix@$i" 2>/dev/null || true
    done
done
for unit in tos-pq-privacy tos-pq-transfers tos-pq-elections tos-pq-lite-client tos-pq-observer@{5,6} tos-dht tos-pq-dht tos-validator@{1,2,3,4} tos-pq-validator@{1,2,3,4,7}; do
    pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
    [[ -z "$pid" || "$pid" == 0 ]] || { echo "Refusing to reset data: $unit still owns PID $pid"; exit 1; }
done
# Retire the old classical units and their per-instance overrides.
rm -f /etc/systemd/system/tos-dht.service /etc/systemd/system/tos-validator@*.service
rm -rf /etc/systemd/system/tos-validator@*.service.d
systemctl disable --now tos-rss-monitor.timer 2>/dev/null || true
# Root-run tools write throughout /data, so it is root's before anything is
# written in it: a tos-owned /data would let tos swap directories or plant
# links for root to follow.
mkdir -p /data
chown root:root /data
chmod 0755 /data
if [[ $CLEAN == 1 ]]; then
    # Literal fixed root: never derive this destructive target from an environment variable.
    find /data -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
fi
# The emptiness check above ran while tos may still have owned /data; only
# now that tos cannot add entries does an empty /data mean nothing is planted.
if [[ -n "$(find /data -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
    echo '/data gained entries before it became root-owned; refusing to write into it'; exit 1
fi
id tos >/dev/null 2>&1 || useradd --system --home-dir /data --shell /usr/sbin/nologin tos
mkdir -p /usr/local/share/tos/fift/lib /usr/local/share/tos/smartcont
for pair in 'validator-engine/validator-engine:validator-engine' 'dht-server/dht-server:dht-server' \
    'validator-engine-console/validator-engine-console:validator-console' 'lite-client/lite-client:lite-client' \
    'utils/generate-random-id:genkey' 'crypto/pq/tos-pq-consensus-key:pq-consensus-key' \
    'crypto/create-state:create-state' 'crypto/fift:fift' 'crypto/func:func'; do
    install -m755 "$BUILD/${pair%%:*}" "/usr/local/bin/tos-${pair##*:}"
done
cp -a crypto/fift/lib/. /usr/local/share/tos/fift/lib/
cp -a crypto/smartcont/. /usr/local/share/tos/smartcont/
cp -a "$BUILD/crypto/smartcont/auto" /usr/local/share/tos/smartcont/
cp -a "$STAGING/pool" /data/shielded-pool
PREPARE_ARGS=()
[[ $ROTATE == 0 ]] || PREPARE_ARGS+=(--rotate)
"$UV" run python scripts/local_pq_testnet.py prepare "${PREPARE_ARGS[@]}"
# Everything in /data was written by root just now. Set modes while it is
# all still root's, then hand tos only the directories its daemons write.
chmod 0755 /data/testnet /data/shielded-pool /data/configs
chmod 0644 /data/shielded-pool/* /data/configs/*
find /data/testnet -name 'pq-consensus.seed' -exec chmod 0600 {} +
find /data/testnet -name keyring -type d -exec chmod 0700 {} +
chmod 0700 /data/testnet/state
chown -R tos:tos /data/testnet/node* /data/lite-client
install -m644 "$REPO/scripts/tos-pq-dht.service" /etc/systemd/system/tos-pq-dht.service
install -m644 "$REPO/scripts/tos-pq-validator@.service" /etc/systemd/system/tos-pq-validator@.service
install -m644 "$REPO/scripts/tos-pq-observer@.service" /etc/systemd/system/tos-pq-observer@.service
install -m644 "$REPO/scripts/tos-pq-lite-client.service" /etc/systemd/system/tos-pq-lite-client.service
install -d /usr/local/libexec/tos
install -m755 "$REPO/scripts/run-local-lite-client.py" /usr/local/libexec/tos/run-local-lite-client.py
# The traffic and election services run as root from this checkout. Only root and
# the user who ran this installer may be able to change what they execute; the
# check runs now and again before every start, from a root-owned copy.
install -m755 "$REPO/scripts/check-root-exec-tree.py" /usr/local/libexec/tos/check-root-exec-tree
PYTHON_HOME="$(dirname "$(dirname "$(readlink -f "$REPO/.venv/bin/python")")")"
ROOT_EXEC_CHECK="/usr/bin/python3 /usr/local/libexec/tos/check-root-exec-tree --trusted-uid ${SUDO_UID:-0}"
ROOT_EXEC_CHECK+=" --tree $REPO/scripts --tree $REPO/test/tostester/src"
ROOT_EXEC_CHECK+=" --tree $REPO/.venv --ignore $REPO/.venv/.lock --tree $PYTHON_HOME"
ROOT_EXEC_CHECK+=" --path $BUILD/toslib/libtoslibjson.so"
PRIVACY_GENERATOR="$REPO/tools/shielded-pool-circuit/crosscheck/target/release/local_pool_traffic"
$ROOT_EXEC_CHECK --path "$PRIVACY_GENERATOR"
systemctl daemon-reload
systemd-analyze verify tos-pq-dht.service tos-pq-validator@1.service tos-pq-observer@5.service tos-pq-lite-client.service
python3 - <<'CHECK'
import os, socket, time
from pathlib import Path
def sample():
    return list(map(int, Path('/proc/stat').read_text().splitlines()[0].split()[1:9]))
a=sample(); time.sleep(1); b=sample(); d=[y-x for x,y in zip(a,b)]
busy=os.cpu_count()*(1-(d[3]+d[4])/max(1,sum(d)))
m=dict(line.split(':',1) for line in Path('/proc/meminfo').read_text().splitlines())
total=int(m['MemTotal'].split()[0]); available=int(m['MemAvailable'].split()[0])
print(f'Network admission: CPU used {busy:.1f}/{os.cpu_count()}, memory available {available/1024**2:.1f} GiB')
if busy+32 > os.cpu_count()*2/3 or total-available+31*1024**2 > total*2/3:
    raise SystemExit('Network resource budget unavailable')
for port in [*range(2001,2023), *range(8011,8018)]:
    for kind in (socket.SOCK_STREAM, socket.SOCK_DGRAM):
        with socket.socket(socket.AF_INET, kind) as s:
            s.bind(('127.0.0.1',port))
CHECK
systemctl enable --now tos-pq-dht tos-pq-validator@{1,2,3,4} tos-pq-observer@{5,6}
cat > /etc/systemd/system/tos-pq-privacy.service <<UNIT
[Unit]
Description=TOS development random shielded pool verification
After=tos-pq-validator@1.service tos-pq-observer@6.service
ConditionPathExists=/data/configs/privacy-test.json
[Service]
Type=simple
User=root
Group=root
UMask=0077
WorkingDirectory=$REPO
Environment=PYTHONPATH=$REPO/test/tostester/src:$REPO/scripts
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=RAYON_NUM_THREADS=4
ExecStartPre=$ROOT_EXEC_CHECK --path $PRIVACY_GENERATOR
ExecStart=$REPO/.venv/bin/python $REPO/scripts/local-pq-privacy.py
Restart=no
CPUQuota=400%
MemoryMax=12G
KillMode=control-group
[Install]
WantedBy=multi-user.target
UNIT
cat > /etc/systemd/system/tos-pq-transfers.service <<UNIT
[Unit]
Description=TOS development random transfer verification
After=tos-pq-validator@1.service tos-pq-observer@6.service
ConditionPathExists=/data/configs/transfer-test.json
[Service]
Type=simple
User=root
Group=root
UMask=0077
WorkingDirectory=$REPO
Environment=PYTHONPATH=$REPO/test/tostester/src:$REPO/scripts
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStartPre=$ROOT_EXEC_CHECK
ExecStart=$REPO/.venv/bin/python $REPO/scripts/local-pq-transfers.py
Restart=no
CPUQuota=100%
MemoryMax=1G
KillMode=control-group
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
if [[ $ROTATE == 1 ]]; then
    systemctl enable --now tos-pq-validator@7
    cat > /etc/systemd/system/tos-pq-elections.service <<UNIT
[Unit]
Description=TOS development ten-minute PQ elections
After=tos-pq-validator@1.service tos-pq-validator@7.service
[Service]
Type=simple
User=root
Group=root
UMask=0077
WorkingDirectory=$REPO
Environment=PYTHONPATH=$REPO/test/tostester/src:$REPO/scripts
ExecStartPre=$ROOT_EXEC_CHECK
ExecStart=$REPO/.venv/bin/python $REPO/scripts/local-pq-elections.py
# The driver re-reads the elector on every pass, so a restart loses nothing.
# Left dead after one transient lite-server error it misses a whole election
# window, and an election nobody staked into closes empty.
Restart=on-failure
RestartSec=30
CPUQuota=100%
MemoryMax=1G
KillMode=control-group
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
fi
"$UV" run python scripts/local_pq_testnet.py deploy
systemctl enable --now tos-pq-lite-client
[[ $ROTATE == 0 ]] || systemctl enable --now tos-pq-elections
printf '\nFour PQ validators, two observers, lite-client and the local development pool are running.\n'
"$REPO/scripts/testnet-ctl.sh" status
