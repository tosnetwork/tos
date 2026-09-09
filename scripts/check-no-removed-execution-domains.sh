#!/usr/bin/env bash
set -euo pipefail

# EVM remains a removed execution domain. Uno is approved only as the wc=2
# confidential-amount BlockTransition engine.
# The former independent-asset and shielded-pool implementations remain banned.
# Bridge exclusions apply to the execution-domain scan, not the retired-symbol
# scan. Public execution-registry policy:
# https://github.com/tosnetwork/constitution/blob/main/tos-blockchain/workchain-execution-registry.md
exec python3 - "${1:-.}" <<'PY'
import fnmatch
from pathlib import Path
import re
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
# Keep the existing infrastructure exclusions, not blanket source extensions.
self_excluded = {
    "scripts/check-no-removed-execution-domains.sh",
    ".github/workflows/no-removed-execution-domains-scan.yml",
}
bridge_excluded = {
    "scripts/verify-token-bridge.py", "scripts/build-token-bridge.sh",
    "scripts/verify-coin-bridge.py", "scripts/build-coin-bridge.sh",
    "scripts/test-coin-bridge-tvm.sh", "scripts/test-coin-bridge-evm.sh",
    "scripts/test-token-bridge-tvm.sh", "scripts/test-token-bridge-tron.sh",
    ".github/workflows/bridge-validation.yml",
}
uno_paths = (
    "uno/**", "doc/uno-*", "doc/measurements/uno-*",
    "crypto/block/workchain-*", "crypto/test/test-workchain*",
    "crypto/test/workchain-*", "test/test-uno-*", "test/counter-*",
    "crypto/block/block.tlb", "scripts/m1-real-manager-sync.py",
    "crypto/block/block-parse.cpp", "crypto/block/transaction.cpp",
    "assembly/native/build-ubuntu-shared.sh",
    "assembly/native/build-ubuntu-appimages.sh",
    "assembly/native/build-ubuntu-portable.sh",
    "validator/impl/collator.cpp", "validator/impl/validate-query.cpp",
    "validator-engine/CMakeLists.txt",
    "doc/workchain-native-ingress-policy.md",
    "scripts/measure-uno-audit-wave4.sh", "test/uno-snapshot-transport.*",
    ".github/workflows/build-tos-linux-x86-64-shared.yml",
    ".github/workflows/build-tos-linux-arm64-shared.yml",
    ".github/workflows/build-tos-linux-x86-64-appimage.yml",
    ".github/workflows/build-tos-linux-arm64-appimage.yml",
    ".github/workflows/uno-wallet-prover.yml",
)
# Exact cache-option help/comment lines; this does not exempt root build code.
crypto_cache_lines = {
    '# AUTO enables the isolated UNO crypto checks when their pinned native toolchain',
    '"UNO crypto tests: AUTO, ON, or OFF" FORCE)',
    '"UNO crypto tests: AUTO, ON, or OFF")',
    'set(TOS_UNO_CRYPTO_PROTOTYPE_TESTS "AUTO" CACHE STRING "UNO crypto tests: AUTO, ON, or OFF")',
}
# A path-and-word exception never suppresses another forbidden identifier.
exceptions = {
    # Standard mnemonic dictionary data.
    "sdk/js/packages/crypto/src/mnemonic/wordlist.ts": {"orchard"},
    # Standard mnemonic dictionary data.
    "test/tostester/src/pytosiq_core/crypto/keys.py": {"orchard"},
    # Standard mnemonic dictionary data.
    "toslib/toslib/keys/bip39.cpp": {"orchard"},
    # Negative dependency gate's own forbidden-name declarations.
    "uno/crypto/tests/kernel-gates.py": {"orchard", "halo2_proofs", "halo2_gadgets"},
    # Archived traceback quotes the negative dependency gate's forbidden names.
    "doc/measurements/uno-m2-rng-controls.json": {"orchard", "halo2_proofs"},
    # Verbatim stderr from the same negative dependency gate control.
    "doc/measurements/uno-m2-rng-controls/expanded-dependency-gate.stderr.log": {"orchard", "halo2_proofs"},
}
negative_dependency_rules = {
    'self.assertFalse(names & {"rand", "getrandom", "rand_chacha", "orchard", "halo2_proofs"}, graph)',
    'self.assertFalse(any(p["name"] in {"orchard", "halo2_proofs", "halo2_gadgets"} for p in packages))',
}
# Independent mining/asset names forbidden by the V2 removal decision.
# mine_uno and uno_sendMineUno additionally occur in cd8e170a0^:
# tosctl/uno/src/mine.rs and validator-engine/json-rpc-server.cpp.
# Pool dependencies were removed from the kernel by 8674dc19d.
retired = re.compile(
    r"MineUno|mine_uno|UnoToken|UNO\s+Token|uno_supply|uno_halving|uno_subsidy"
    r"|\b(?:orchard|halo2)[A-Za-z0-9_]*|\bred_?pallas\b|mine-uno", re.IGNORECASE)
# Identifier components count too, without matching unrelated unordered_* names.
uno = re.compile(r"(?i:\buno\b|(?:\b|_)uno(?=_|\b))|(?:\b|_)[Uu][Nn][Oo](?=[A-Z])|(?<=[a-z0-9])Uno(?![a-z])")
evm = re.compile(r"\bevm\b")  # Preserve the existing execution-domain rule.
paths = subprocess.check_output(["git", "-C", str(root), "ls-files", "-z"]).split(b"\0")
failed = False
scanned = set()
binary_skipped = 0
directory_skipped = 0
for raw in paths:
    if not raw:
        continue
    path = raw.decode("utf-8", "surrogateescape")
    if path.startswith("third-party/") or path in self_excluded:
        continue
    file = root / path
    # Tracked submodule directories are not files, matching the old grep scan.
    if file.is_dir():
        directory_skipped += 1
        continue
    try:
        data = file.read_bytes()
    except OSError as error:
        print(f"{path}: scan failed: {error}", file=sys.stderr)
        failed = True
        continue
    if b"\0" in data:
        if file.suffix.lower() in {".c", ".cc", ".cpp", ".h", ".hpp", ".rs", ".py", ".sh", ".cmake", ".tlb", ".toml", ".json", ".yml", ".yaml", ".js", ".ts", ".tol", ".fc", ".fif", ".func"} or file.name == "CMakeLists.txt":
            print(f"{path}: NUL in source/build file; refusing silent skip", file=sys.stderr)
            failed = True
        binary_skipped += 1
        continue
    scanned.add(path)
    lines = data.decode("utf-8", "surrogateescape").splitlines()
    domain_excluded = path.startswith("crosschain/") or path in bridge_excluded
    approved = any(fnmatch.fnmatchcase(path, pattern) for pattern in uno_paths)
    for number, line in enumerate(lines, 1):
        reasons = []
        if not domain_excluded:
            if evm.search(line):
                reasons.append("removed execution domain")
            # Root build wiring is allowed line-by-line, not file-wide. All
            # matches must be options, paths, targets or labels. Option help and
            # label tails are descriptive text, not unrestricted build commands.
            remaining = re.sub(r"test/uno-snapshot-transport\.(?:cpp|h)|TOS_UNO_[A-Z0-9_]+|(?:test|measure)-uno-[A-Za-z0-9_$\{\}-]+"
                               r"|uno/[A-Za-z0-9_./$\{\}-]+|uno_split_shape|uno_large_snapshot"
                               r"|UNO_CONTEXT_VECTORS_PATH|UNO_SNAPSHOT_LARGE_TEST"
                               r"|\b_tos_uno_crypto_tests_(?:cache_type|legacy_value)\b"
                               r'|LABELS "uno;[^"]*"', "", line)
            cmake_line = path == "CMakeLists.txt" and "/../" not in line and (
                not uno.search(remaining) or
                line.strip() in crypto_cache_lines or
                bool(re.fullmatch(r'\s*option\(TOS_UNO_[A-Z0-9_]+ "[^"]*" (?:ON|OFF)\)\s*', line)))
            if uno.search(line) and not approved and not cmake_line:
                reasons.append("Uno outside approved engine paths")
        if not path.lower().endswith(".md"):
            for match in retired.finditer(line):
                exempt = match.group() in exceptions.get(path, set())
                if path == "uno/crypto/tests/kernel-gates.py":
                    exempt = exempt and line.strip() in negative_dependency_rules
                if not exempt:
                    reasons.append("retired implementation symbol: " + match.group())
                    if path == "uno/crypto/tests/kernel-gates.py":
                        reasons.append("declaration is not an approved negative-gate assertion")
        if reasons:
            print(f"{path}:{number}: {'; '.join(reasons)}: {line}", file=sys.stderr)
            failed = True
if not {"CMakeLists.txt", "crypto/block/block.cpp"} <= scanned:
    print("scan failed: required source anchors were not read", file=sys.stderr)
    failed = True
if failed:
    print("removed-execution-domain scan failed", file=sys.stderr)
    sys.exit(1)
print(f"removed-execution-domain scan passed: {len(scanned)} text files, {binary_skipped} binary files and {directory_skipped} directories skipped")
PY
