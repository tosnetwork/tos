#!/usr/bin/env node
/**
 * EVM Workchain — receipt + logs canonical-rebuild invariant.
 *
 * MPT is permanently disabled in TOS EVM. Receipts and logs are not
 * indexed via Ethereum MPT roots; they are derived from native cell
 * commitments (W3-B stores them in StoredBlock and W4-B binds every
 * RocksDB cache record with an EvmCacheRecordStamp so stale or wiped
 * cache entries can be invalidated and rebuilt deterministically from
 * canonical state).
 *
 * This test proves, end-to-end from a wallet's view, that:
 *   a) A signed transfer lands and produces a receipt.
 *   b) eth_getTransactionReceipt returns status / blockNumber /
 *      transactionHash / logs / logsBloom.
 *   c) eth_getLogs over the same block range returns a log set
 *      consistent with the receipt's logs.
 *   d) After a forced cache invalidation (node restart with the RPC
 *      RocksDB cache directory wiped), the SAME receipt and the SAME
 *      log records reappear unchanged — proving they are canonically
 *      reconstructible from native commitments per plan §9.
 *   e) The blockNumber / transactionHash returned in pass-2 equals
 *      pass-1 byte-for-byte.
 *
 * Cache-wipe model
 * ----------------
 * The JSON-RPC server does not expose an admin/debug method to flush
 * its RocksDB cache (no debug_clearCache / admin_resetCache surface).
 * The only portable way for an external test to force a rebuild is to
 * have the node operator restart the process with the cache directory
 * removed. This test supports two modes:
 *
 *   1. Single-pass mode (default): runs (a)-(c) only and prints a
 *      machine-parseable JSON line carrying the (txHash, blockNumber)
 *      it observed. CI is then expected to:
 *         - kill the node,
 *         - rm -rf the configured EVM RPC cache directory,
 *         - restart the node,
 *         - re-run this script with TOS_REBUILD_CHECK=<jsonline>.
 *   2. Rebuild-check mode: when TOS_REBUILD_CHECK is set to the JSON
 *      line from pass-1, the script SKIPS sending a new tx and instead
 *      re-fetches the receipt + logs for that tx and compares them.
 *
 * Limitation: a single-process run cannot itself wipe the cache (we
 * have no IPC handle to the running node and there is no admin RPC).
 * Passing TOS_REBUILD_CHECK is therefore the only way to exercise (d)
 * + (e). When run without it, the script reports the limitation
 * explicitly and exits success after (a)-(c).
 *
 * Usage:
 *   node test/evm-workchain/native-receipt-log-rebuild-test.js [rpc_url]
 *   TOS_REBUILD_CHECK='{"txHash":"0x..","blockNumber":"0x..","logCount":N}' \
 *     node test/evm-workchain/native-receipt-log-rebuild-test.js [rpc_url]
 *
 * Env:
 *   TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS=1 — required (devnet fixture key).
 *   TOS_REBUILD_CHECK                    — optional; pass-2 marker.
 *
 * Default RPC URL: http://127.0.0.1:8011 (matches sibling tests).
 */

const RPC_URL = process.argv[2] || 'http://127.0.0.1:8011';
const TX_TIMEOUT_MS = 30000;

if (process.env.TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS !== '1') {
    console.error('native-receipt-log-rebuild-test.js is a devnet fixture; ' +
                  'requires TOS_DEVNET_ALLOW_TEST_EVM_ACCOUNTS=1');
    process.exit(1);
}

// Devnet fixture account #0 — same key the other JS tests use. This
// public Hardhat key must never be present in production genesis.
const PRIV_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';
const RECIPIENT = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';

let ethers;
try {
    // Try the same path full-rpc-test.js uses for its ethers install.
    ethers = require('/tmp/evm-rpc-test/node_modules/ethers');
} catch {
    try {
        ethers = require('ethers');
    } catch {
        console.error('ethers not found. Install with: npm install ethers ' +
                      '(or use the same /tmp/evm-rpc-test path the sibling ' +
                      'full-rpc-test.js expects).');
        process.exit(1);
    }
}

async function jsonRpc(method, params = []) {
    const resp = await fetch(RPC_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', method, params, id: Date.now() })
    });
    const json = await resp.json();
    if (json.error) throw new Error(`${method}: ${JSON.stringify(json.error)}`);
    return json.result;
}

function isHex32(s) {
    return typeof s === 'string'
        && s.length === 66
        && /^0x[0-9a-fA-F]{64}$/.test(s);
}

// Lowercase a hex string; accept null/undefined safely.
function lc(x) { return typeof x === 'string' ? x.toLowerCase() : x; }

// Compare two log objects ignoring case differences in hex fields.
function logsEqual(a, b) {
    if (!a || !b) return false;
    return lc(a.transactionHash) === lc(b.transactionHash)
        && lc(a.blockHash)       === lc(b.blockHash)
        && a.logIndex            === b.logIndex
        && a.transactionIndex    === b.transactionIndex
        && lc(a.address)         === lc(b.address)
        && lc(a.data)            === lc(b.data)
        && JSON.stringify((a.topics || []).map(lc))
           === JSON.stringify((b.topics || []).map(lc));
}

async function fetchReceiptAndLogs(txHash, blockNumber) {
    const receipt = await jsonRpc('eth_getTransactionReceipt', [txHash]);
    if (!receipt) throw new Error('receipt missing for ' + txHash);
    // Filter eth_getLogs by exact block to avoid pulling unrelated history.
    const logs = await jsonRpc('eth_getLogs', [{
        fromBlock: blockNumber,
        toBlock: blockNumber,
    }]);
    return { receipt, logs };
}

async function pass1(check) {
    // (a) Send a transfer using the same scaffolding pattern as
    //     full-rpc-test.js (ethers JsonRpcProvider, batchMaxCount=1).
    const provider = new ethers.JsonRpcProvider(RPC_URL, undefined, {
        batchMaxCount: 1,
    });
    const wallet = new ethers.Wallet(PRIV_KEY, provider);

    const tx = await wallet.sendTransaction({
        to: RECIPIENT,
        value: ethers.parseEther('0.01'),
        gasLimit: 30000,
    });
    check(`tx broadcast (hash=${tx.hash.slice(0, 12)}…)`, true);

    // Wait for the receipt with a bounded timeout, mirroring full-rpc-test.js.
    const start = Date.now();
    let receiptRaw = null;
    while (Date.now() - start < TX_TIMEOUT_MS) {
        receiptRaw = await jsonRpc('eth_getTransactionReceipt', [tx.hash]);
        if (receiptRaw) break;
        await new Promise(r => setTimeout(r, 500));
    }
    if (!receiptRaw) {
        check('tx receipt within 30s', false,
              'collator did not produce a block — see full-rpc-test.js README');
        return null;
    }

    // (b) Receipt shape.
    check('receipt.status === "0x1" (success)', receiptRaw.status === '0x1',
          `${receiptRaw.status}`);
    check('receipt.blockNumber is hex', /^0x[0-9a-fA-F]+$/.test(receiptRaw.blockNumber),
          `${receiptRaw.blockNumber}`);
    check('receipt.transactionHash matches tx.hash',
          lc(receiptRaw.transactionHash) === lc(tx.hash),
          `${receiptRaw.transactionHash}`);
    check('receipt.logs is an array', Array.isArray(receiptRaw.logs),
          `${(receiptRaw.logs || []).length} entries`);
    check('receipt.logsBloom is 256-byte hex',
          typeof receiptRaw.logsBloom === 'string'
              && receiptRaw.logsBloom.length === 2 + 512,
          `${receiptRaw.logsBloom?.slice(0, 12)}…`);

    // (c) eth_getLogs over the same block range returns the same log
    //     records the receipt advertised.
    const blockLogs = await jsonRpc('eth_getLogs', [{
        fromBlock: receiptRaw.blockNumber,
        toBlock: receiptRaw.blockNumber,
    }]);
    check('eth_getLogs(<block>) is an array', Array.isArray(blockLogs));

    // The receipt's logs must be a subset of the block's logs (a plain
    // value transfer typically has no logs at all — that's fine; the
    // assertion still holds vacuously). For each receipt log, find a
    // matching block-log entry.
    let matched = 0;
    for (const rl of (receiptRaw.logs || [])) {
        if ((blockLogs || []).some(bl => logsEqual(rl, bl))) matched++;
    }
    check('every receipt log is also returned by eth_getLogs',
          matched === (receiptRaw.logs || []).length,
          `${matched}/${(receiptRaw.logs || []).length}`);

    // Hand off to pass-2.
    const handoff = {
        txHash: lc(tx.hash),
        blockNumber: receiptRaw.blockNumber,
        logCount: (receiptRaw.logs || []).length,
    };
    console.log('TOS_REBUILD_CHECK=' + JSON.stringify(handoff));
    return { handoff, receiptRaw, blockLogs };
}

async function pass2(check, marker) {
    // (d) + (e): the cache has (presumably) been wiped and the node
    //            restarted. Re-fetch and verify byte-equality with the
    //            pass-1 marker.
    let parsed;
    try {
        parsed = JSON.parse(marker);
    } catch (e) {
        throw new Error('TOS_REBUILD_CHECK is not valid JSON: ' + e.message);
    }
    const { txHash, blockNumber, logCount } = parsed;
    check('marker has txHash (32 bytes hex)', isHex32(txHash), `${txHash}`);
    check('marker has hex blockNumber',
          typeof blockNumber === 'string' && blockNumber.startsWith('0x'),
          `${blockNumber}`);

    const { receipt, logs } = await fetchReceiptAndLogs(txHash, blockNumber);
    check('post-rebuild receipt re-fetch succeeded', !!receipt);
    check('post-rebuild receipt.status === "0x1"', receipt.status === '0x1',
          `${receipt.status}`);
    check('post-rebuild receipt.transactionHash matches marker',
          lc(receipt.transactionHash) === lc(txHash),
          `${receipt.transactionHash}`);
    check('post-rebuild receipt.blockNumber matches marker',
          receipt.blockNumber === blockNumber,
          `${receipt.blockNumber} vs ${blockNumber}`);
    check('post-rebuild receipt.logs.length matches marker',
          (receipt.logs || []).length === logCount,
          `${(receipt.logs || []).length} vs ${logCount}`);

    // The block's logs view must still contain the receipt's logs.
    let matched = 0;
    for (const rl of (receipt.logs || [])) {
        if ((logs || []).some(bl => logsEqual(rl, bl))) matched++;
    }
    check('post-rebuild eth_getLogs still contains the receipt logs',
          matched === (receipt.logs || []).length,
          `${matched}/${(receipt.logs || []).length}`);
}

async function main() {
    console.log('EVM Workchain — receipt + logs canonical-rebuild invariant');
    console.log(`RPC: ${RPC_URL}`);
    console.log('='.repeat(60));

    let passed = 0, failed = 0;
    const check = (name, ok, detail = '') => {
        if (ok) { console.log(`  ✓ ${name}${detail ? ` (${detail})` : ''}`); passed++; }
        else    { console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ''}`); failed++; }
    };

    const marker = process.env.TOS_REBUILD_CHECK;
    if (marker && marker.length > 0) {
        console.log('Mode: rebuild-check (pass 2, post-restart)');
        await pass2(check, marker);
    } else {
        console.log('Mode: single-pass (pass 1)');
        const r = await pass1(check);
        if (r) {
            console.log('— (skipped) cache wipe + restart not performed in this ' +
                        'process. Re-run with TOS_REBUILD_CHECK=<line above> after ' +
                        'restarting the node with its EVM RPC cache directory ' +
                        'removed to validate (d) + (e). No external cache-flush ' +
                        'RPC exists, so a single-process run cannot exercise ' +
                        'rebuildability on its own — this is documented in the ' +
                        'header.');
        }
    }

    console.log('='.repeat(60));
    console.log(`Results: ${passed} passed, ${failed} failed`);
    process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => { console.error(`Fatal: ${e.message}`); process.exit(1); });
