#!/usr/bin/env bash
set -euo pipefail

root="${1:-.}"
core="$root/evm/core"
create_state="$root/crypto/block/create-state.cpp"
pow_giver="$root/evm/contracts/EToSPoWGiver.sol"
pow_giver_fift="$root/crypto/smartcont/etos-pow-givers.fif"
rpc_handlers="$root/evm/rpc/handlers.cpp"
compute_phase="$root/evm/core/compute-phase.cpp"
post_accept="$root/evm/core/post-accept.cpp"
rpc_cache_db="$root/evm/rpc/cache-db.cpp"
validator_download_state="$root/validator/net/download-state.cpp"
validator_token_manager="$root/validator/token-manager.cpp"
harness_paths=(
    "$root/test/conformance/hive/clients/tos/bootstrap-validators.sh"
    "$root/test/conformance/hive/clients/tos/tos.cmd"
    "$root/test/tostester/src/tostester/zerostate.py"
)

if rg -n "test test test test test test test test test test test junk|ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" "$core"; then
    echo "evm production hardening check failed: public test mnemonic/private key must not live under evm/core" >&2
    exit 1
fi

if rg -n 'def_stack_word\("evm-zerostate-accounts-cell ' "$create_state"; then
    echo "evm production hardening check failed: legacy zero-arg EVM zerostate Fift word must not be registered" >&2
    exit 1
fi

if rg -n 'evm-zerostate-accounts-cell|builtin-10-EOAs|built-in 10 EOAs' "${harness_paths[@]}"; then
    echo "evm production hardening check failed: EVM bootstrap harness must not fall back to public test accounts" >&2
    exit 1
fi

hardhat_fixture_hits=$(
    rg -l "test test test test test test test test test test test junk|ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" \
        "$root/doc" "$root/test" "$root/scripts" 2>/dev/null || true
)
for hit in $hardhat_fixture_hits; do
    [ "$hit" = "$root/scripts/check-evm-production-hardening.sh" ] && continue
    if ! rg -q 'TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS|devnet fixture|Devnet-Only Hardhat Fixture Accounts' "$hit"; then
        echo "evm production hardening check failed: public Hardhat fixture key must be explicitly devnet-gated in $hit" >&2
        exit 1
    fi
done

if rg -n 'seed[[:space:]]*=[[:space:]]*blockhash\(block\.number - 1\)' "$pow_giver"; then
    echo "evm production hardening check failed: EToSPoWGiver must not rotate seed to parent blockhash alone" >&2
    exit 1
fi

if ! rg -q 'seed[[:space:]]*=[[:space:]]*keccak256\(abi\.encodePacked' "$pow_giver"; then
    echo "evm production hardening check failed: EToSPoWGiver must derive a per-success replay-resistant seed" >&2
    exit 1
fi

if ! rg -q 'metadata\.bytecodeHash=none|metadata hash disabled' "$pow_giver_fift"; then
    echo "evm production hardening check failed: embedded EToSPoWGiver bytecode must document deterministic metadata settings" >&2
    exit 1
fi

if ! rg -q 'TOS_EVM_DEBUG_RPC_TOKEN' "$rpc_handlers"; then
    echo "evm production hardening check failed: debug_rebuildRpcCache must require admin auth even under TOS_ENABLE_EVM_DEBUG_RPC" >&2
    exit 1
fi

budget_line=$(rg -n 'EVM stateRoot budget exceeded before execution|rejecting EVM tx before execution' "$compute_phase" | head -n1 | cut -d: -f1 || true)
exec_line=$(rg -n 'execute_evm_transaction\(decoded\.txn' "$compute_phase" | head -n1 | cut -d: -f1 || true)
if [ -z "$budget_line" ] || [ -z "$exec_line" ] || [ "$budget_line" -ge "$exec_line" ]; then
    echo "evm production hardening check failed: EVM stateRoot budget preflight must run before transaction execution" >&2
    exit 1
fi
prevalidate_line=$(rg -n 'prevalidate_evm_transaction_admission\(.*decoded\.txn|prevalidate_evm_transaction_admission\(' "$compute_phase" | head -n1 | cut -d: -f1 || true)
if [ -z "$prevalidate_line" ] || [ "$prevalidate_line" -ge "$budget_line" ]; then
    echo "evm production hardening check failed: cheap EVM tx prevalidation must run before stateRoot budget scan" >&2
    exit 1
fi

if ! rg -q 'kMaxSimulateEmittedBlocks' "$rpc_handlers" ||
   ! rg -q 'simulated block gap too large' "$rpc_handlers" ||
   ! rg -q 'kMaxSimulateResponseBytes' "$rpc_handlers"; then
    echo "evm production hardening check failed: eth_simulateV1 must cap total emitted filler blocks and response bytes" >&2
    exit 1
fi

if rg -n 'kMaxSimulateFillerJump[[:space:]]*=[[:space:]]*8192' "$rpc_handlers"; then
    echo "evm production hardening check failed: eth_simulateV1 must not rely on the old per-entry 8192 filler cap" >&2
    exit 1
fi

if ! rg -q 'kMaxPersistentStateDownloadBytes' "$validator_download_state" ||
   ! rg -q 'persistent state stream exceeds advertised size|persistent state too large' "$validator_download_state" ||
   ! rg -q 'download_started_' "$root/validator/net/download-state.hpp"; then
    echo "evm production hardening check failed: persistent state downloader must validate total and cumulative size before streaming" >&2
    exit 1
fi

if rg -n 'request_total_size\(\);[[:space:]]*got_block_state_part' "$validator_download_state"; then
    echo "evm production hardening check failed: persistent state downloader must not start slices before total size is verified" >&2
    exit 1
fi

if ! rg -q 'compute_storage_root_for_account' "$rpc_handlers"; then
    echo "evm production hardening check failed: eth_getProof must use real storage roots for non-target accounts" >&2
    exit 1
fi

if rg -n 'For non-target accounts we use kEmptyRoot|other_addr == addr\) their_storage_hash = storage_hash' "$rpc_handlers"; then
    echo "evm production hardening check failed: eth_getProof must not approximate non-target storage roots as empty" >&2
    exit 1
fi

if ! rg -q 'put_incomplete_transaction|put_incomplete_block|has_incomplete_transaction|has_incomplete_block' "$rpc_cache_db" ||
   ! rg -q 'hydrate_evm_rpc_incomplete_indexes_from_cache|has_incomplete_transaction|has_incomplete_block' "$post_accept"; then
    echo "evm production hardening check failed: post-accept incomplete indexes must be durable and restart-hydrated" >&2
    exit 1
fi

if rg -n 'it->second\.promise\.set_value\(gen_token\(size, priority\)\)' "$validator_token_manager"; then
    echo "evm production hardening check failed: TokenManager must wake pending requests with their own size/priority" >&2
    exit 1
fi

if [[ "${TOS_CHECK_ETOS_GIVER_BYTECODE:-0}" == "1" ]]; then
    if ! command -v node >/dev/null 2>&1; then
        echo "evm production hardening check failed: node is required for EToSPoWGiver bytecode equivalence check" >&2
        exit 1
    fi
    node - "$root" <<'NODE'
const fs = require('fs');
const path = require('path');
const cp = require('child_process');

const root = process.argv[2];
const sourcePath = path.join(root, 'evm/contracts/EToSPoWGiver.sol');
const fiftPath = path.join(root, 'crypto/smartcont/etos-pow-givers.fif');
const source = fs.readFileSync(sourcePath, 'utf8');
const input = {
  language: 'Solidity',
  sources: {'evm/contracts/EToSPoWGiver.sol': {content: source}},
  settings: {
    optimizer: {enabled: true, runs: 200},
    metadata: {bytecodeHash: 'none'},
    outputSelection: {'*': {'*': ['evm.deployedBytecode.object']}}
  }
};

let output = null;
let compiler = null;
const choices = [];
if (process.env.TOS_SOLC_0_8_26) {
  choices.push([process.env.TOS_SOLC_0_8_26, ['--standard-json']]);
}
if (process.env.HOME) {
  choices.push([path.join(process.env.HOME, '.solcx/solc-v0.8.26'), ['--standard-json']]);
}
if (process.env.TOS_ALLOW_NPX_SOLC === '1') {
  choices.push(['npx', ['--yes', 'solc@0.8.26', '--standard-json']]);
}
try {
  const version = cp.execFileSync('solc', ['--version'], {
    encoding: 'utf8',
    timeout: 10000,
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  if (/Version:\s+0\.8\.26\+|^0\.8\.26\+/.test(version)) {
    choices.push(['solc', ['--standard-json']]);
  }
} catch (_) {
  // solc is optional; pinned local and npx fallbacks are tried above.
}
for (const choice of choices) {
  try {
    output = cp.execFileSync(choice[0], choice[1], {
      input: JSON.stringify(input),
      encoding: 'utf8',
      maxBuffer: 20 * 1024 * 1024,
      timeout: 30000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    compiler = [choice[0], ...choice[1]].join(' ');
    break;
  } catch (_) {
    // Try the next compiler source.
  }
}
if (!output) {
  console.error('evm production hardening check failed: cannot run pinned solc 0.8.26 standard-json (set TOS_SOLC_0_8_26, install $HOME/.solcx/solc-v0.8.26, install solc 0.8.26, or set TOS_ALLOW_NPX_SOLC=1 for local npx fallback)');
  process.exit(1);
}

const json = JSON.parse(output.slice(output.indexOf('{')));
if (json.errors) {
  const errors = json.errors.filter((e) => e.severity === 'error');
  if (errors.length !== 0) {
    console.error(errors.map((e) => e.formattedMessage || e.message).join('\n'));
    process.exit(1);
  }
}
const compiled = json.contracts['evm/contracts/EToSPoWGiver.sol'].EToSPoWGiver.evm.deployedBytecode.object;
const fift = fs.readFileSync(fiftPath, 'utf8');
const match = fift.match(/"([0-9a-f]+)" x>B constant etos-giver-code/);
if (!match) {
  console.error('evm production hardening check failed: etos-giver-code literal not found');
  process.exit(1);
}
if (match[1] !== compiled) {
  console.error(`evm production hardening check failed: embedded EToSPoWGiver bytecode does not match source (${compiler})`);
  console.error(`compiled bytes=${compiled.length / 2}, embedded bytes=${match[1].length / 2}`);
  process.exit(1);
}
console.log(`EToSPoWGiver bytecode matches source (${compiled.length / 2} bytes, ${compiler})`);
NODE
fi

echo "evm production hardening check passed"
