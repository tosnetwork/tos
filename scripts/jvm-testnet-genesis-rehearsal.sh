#!/usr/bin/env bash
# jvm-testnet-genesis-rehearsal.sh
#
# Phase X — runnable end-to-end rehearsal of the wc=3 testnet
# genesis ceremony.  Verifies that a clean checkout produces:
#
#   * a deterministic rt.jar (the value committed into
#     ConfigParam 85 as `stdlib_hash`)
#   * a wc=3 ShardState seeded with one Deployer + one Wallet at
#     deterministic addresses (the launch state that lets the
#     chain process any further deploys)
#
# Both outputs are content-addressable: every operator who runs
# this script with the same toolchain MUST get the same sha256s.
# A divergence at any layer means that operator's environment
# would produce a genesis the rest of the network rejects — catch
# it BEFORE launch day, not at activation.
#
# Outputs (printed at end of run):
#
#   - stdlib_hash (sha256 of rt.jar)            — committed to ConfigParam 85
#   - jvmstate3 root hash                       — committed to ConfigParam 12
#   - jvmstate3 file hash                       — distributed with the zerostate BOC
#
# Substitutions for a real launch:
#
#   - The Wallet/Deployer owner pubkeys and salts in
#     `crypto/smartcont/jvm-testnet-rehearsal.fif` are
#     deterministic test fixtures.  Replace with the launch's
#     actual keypairs (operator decision; out of this script's
#     scope) before producing the production zerostate.
#
# This script is read-only on the source tree — all build /
# extraction work happens in a tmpdir which is printed at the
# end for inspection.

set -euo pipefail

# Resolve the repo root from this script's location so the
# rehearsal works from any cwd.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

# Pin the build platform; rt.jar reproducibility requires a
# canonical toolchain (see doc/jvm-rt-reproducibility.md §5).
# The Phase W CI workflow uses ubuntu-22.04 + openjdk-8-jdk-
# headless; local runs SHOULD match.
PLATFORM="${JVM_REHEARSAL_PLATFORM:-linux-x86_64}"
JAVA_VERSION="${JVM_REHEARSAL_JAVA_VERSION:-8}"

echo "=== Phase X: testnet genesis rehearsal ==="
echo "  repo:      ${REPO_ROOT}"
echo "  platform:  ${PLATFORM}"
echo "  java:      ${JAVA_VERSION}"
echo

# ─── Step 1: build rt.jar deterministically ────────────────────────
echo "[1/5] Building rt.jar..."
make -C jvm/avata java-version="${JAVA_VERSION}" \
  "build/${PLATFORM}/rt.jar" > /dev/null
RT_JAR="${REPO_ROOT}/jvm/avata/build/${PLATFORM}/rt.jar"
# Phase DD: use the canonical algorithm (domain-tagged + length-
# prefixed sha256), NOT plain sha256.  See
# `jvm/avata/tools/compute-stdlib-hash.py` and
# `doc/jvm-rt-reproducibility.md §2.1`.
STDLIB_HASH=$(python3 "${REPO_ROOT}/jvm/avata/tools/compute-stdlib-hash.py" "${RT_JAR}")
echo "  rt.jar:        ${RT_JAR}"
echo "  rt.jar size:   $(stat -c '%s' "${RT_JAR}" 2>/dev/null || stat -f '%z' "${RT_JAR}") bytes"
echo "  stdlib_hash:   ${STDLIB_HASH}"
echo

# ─── Step 2: extract Wallet.class + Deployer.class ─────────────────
WORKDIR=$(mktemp -d -t jvm-rehearsal.XXXXXX)
echo "[2/5] Extracting Wallet.class + Deployer.class to ${WORKDIR}..."
unzip -p "${RT_JAR}" java/lang/Wallet.class > "${WORKDIR}/Wallet.class"
unzip -p "${RT_JAR}" java/lang/Deployer.class > "${WORKDIR}/Deployer.class"
WALLET_SIZE=$(stat -c '%s' "${WORKDIR}/Wallet.class" 2>/dev/null \
              || stat -f '%z' "${WORKDIR}/Wallet.class")
DEPLOYER_SIZE=$(stat -c '%s' "${WORKDIR}/Deployer.class" 2>/dev/null \
                || stat -f '%z' "${WORKDIR}/Deployer.class")
echo "  Wallet.class:    ${WALLET_SIZE} bytes"
echo "  Deployer.class:  ${DEPLOYER_SIZE} bytes"
echo

# ─── Step 3: write stdlib_hash as raw bytes for Fift ───────────────
echo "[3/5] Writing stdlib_hash.bin (32 raw bytes)..."
printf '%s' "${STDLIB_HASH}" | xxd -r -p > "${WORKDIR}/stdlib_hash.bin"
STDLIB_HASH_BIN_SIZE=$(stat -c '%s' "${WORKDIR}/stdlib_hash.bin" 2>/dev/null \
                       || stat -f '%z' "${WORKDIR}/stdlib_hash.bin")
if [ "${STDLIB_HASH_BIN_SIZE}" != "32" ]; then
  echo "ERROR: stdlib_hash.bin is ${STDLIB_HASH_BIN_SIZE} bytes, expected 32"
  exit 1
fi
echo "  ${WORKDIR}/stdlib_hash.bin (32 bytes)"
echo

# ─── Step 4: run create-state on the rehearsal Fift script ─────────
echo "[4/5] Running create-state..."
CREATE_STATE="${REPO_ROOT}/build/crypto/create-state"
if [ ! -x "${CREATE_STATE}" ]; then
  echo "ERROR: ${CREATE_STATE} not found; build the validator-engine"
  echo "       binaries first (e.g. cmake --build build --target create-state)"
  exit 1
fi
FIFT_SCRIPT="${REPO_ROOT}/crypto/smartcont/jvm-testnet-rehearsal.fif"
(
  cd "${WORKDIR}"
  FIFTPATH="${REPO_ROOT}/crypto/fift/lib:${REPO_ROOT}/crypto/smartcont" \
    "${CREATE_STATE}" "${FIFT_SCRIPT}"
)
echo

# ─── Step 5: summarize outputs ─────────────────────────────────────
echo "[5/5] Verification summary"
JVMSTATE_BOC="${WORKDIR}/jvmstate3-rehearsal.boc"
JVMSTATE_RHASH_FILE="${WORKDIR}/jvmstate3-rehearsal.rhash"
JVMSTATE_FHASH_FILE="${WORKDIR}/jvmstate3-rehearsal.fhash"
if [ ! -f "${JVMSTATE_BOC}" ]; then
  echo "ERROR: ${JVMSTATE_BOC} was not produced"
  exit 1
fi
JVMSTATE_BOC_SIZE=$(stat -c '%s' "${JVMSTATE_BOC}" 2>/dev/null \
                     || stat -f '%z' "${JVMSTATE_BOC}")
JVMSTATE_RHASH=$(xxd -p "${JVMSTATE_RHASH_FILE}" | tr -d '\n')
JVMSTATE_FHASH=$(xxd -p "${JVMSTATE_FHASH_FILE}" | tr -d '\n')

echo "  stdlib_hash (canonical, ConfigParam 85): ${STDLIB_HASH}"
echo "  jvmstate3.boc size:                ${JVMSTATE_BOC_SIZE} bytes"
echo "  jvmstate3 root hash:               ${JVMSTATE_RHASH}"
echo "  jvmstate3 file hash:               ${JVMSTATE_FHASH}"
echo
echo "Artifacts written to: ${WORKDIR}"
echo
echo "Cross-operator reproducibility check: every operator running"
echo "this script with the same toolchain MUST see the same three"
echo "hashes above.  Divergence → toolchain mismatch (see"
echo "doc/jvm-rt-reproducibility.md §6 troubleshooting)."
