#!/usr/bin/env node
/**
 * EVM Workchain — native state-root invariants (wallet/RPC client perspective).
 *
 * MPT is permanently disabled in TOS EVM.
 *
 * NOTE for client implementors: the JSON field names `stateRoot`,
 * `transactionsRoot`, `receiptsRoot` returned by eth_getBlockBy* are
 * preserved for wallet deserialization compatibility, but the VALUES
 * are TOS-native commitments (cell hash for state, domain-tagged
 * keccak256 list commitments for transactions and receipts). They are
 * NOT Ethereum MPT roots and MUST NOT be verified against an Ethereum
 * trie. eth_getProof is permanently unsupported (-32601); see
 * no-mpt-rpc-test.js for that side of the contract.
 *
 * This test asserts:
 *   a) eth_getBlockByNumber("latest", false) returns a block whose
 *      stateRoot, transactionsRoot, receiptsRoot are each a 32-byte
 *      hex string (66 chars including 0x).
 *   b) Two back-to-back fetches of the same block return byte-identical
 *      stateRoot / transactionsRoot / receiptsRoot — i.e. the native
 *      commitments are deterministic, not randomly generated each call.
 *   c) The stateRoot is NOT the Ethereum empty-trie root
 *      0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
 *      (any non-empty chain — sibling tests already prove balances >0)
 *      and is NOT all-zero.
 *   d) block.hash is a deterministic 32-byte hex string.
 *
 * Usage:
 *   node test/evm-workchain/native-state-root-test.js [rpc_url]
 *
 * Default RPC URL: http://127.0.0.1:8011 (matches sibling tests).
 */

const RPC_URL = process.argv[2] || 'http://127.0.0.1:8011';

const ETHEREUM_EMPTY_MPT_ROOT =
    '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421';
const ALL_ZERO_32 =
    '0x0000000000000000000000000000000000000000000000000000000000000000';

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

// Case-insensitive 32-byte equality. Ethereum hex is canonically lowercase
// but we don't want a stray uppercase nibble to break the determinism
// assertion — only the byte values matter.
function hex32Eq(a, b) {
    return typeof a === 'string'
        && typeof b === 'string'
        && a.toLowerCase() === b.toLowerCase();
}

async function main() {
    console.log('EVM Workchain — native state-root invariants');
    console.log(`RPC: ${RPC_URL}`);
    console.log('='.repeat(60));

    let passed = 0, failed = 0;
    const check = (name, ok, detail = '') => {
        if (ok) { console.log(`  ✓ ${name}${detail ? ` (${detail})` : ''}`); passed++; }
        else    { console.log(`  ✗ ${name}${detail ? ` — ${detail}` : ''}`); failed++; }
    };

    // (a) Pull "latest" once, validate field shapes.
    const block1 = await jsonRpc('eth_getBlockByNumber', ['latest', false]);
    check('latest block exists', !!block1, block1 ? `#${block1.number}` : 'null');
    if (!block1) {
        console.log('Cannot proceed without a block.');
        process.exit(1);
    }

    check('block.stateRoot is 32-byte hex', isHex32(block1.stateRoot),
        `${block1.stateRoot}`);
    check('block.transactionsRoot is 32-byte hex', isHex32(block1.transactionsRoot),
        `${block1.transactionsRoot}`);
    check('block.receiptsRoot is 32-byte hex', isHex32(block1.receiptsRoot),
        `${block1.receiptsRoot}`);
    check('block.hash is 32-byte hex', isHex32(block1.hash), `${block1.hash}`);

    // (b) Determinism: re-fetch the SAME block by its number (not "latest"
    //     — by the time we issue the second call the chain may have
    //     advanced, which would be a false negative). All four
    //     commitments must be byte-equal.
    const block2 = await jsonRpc('eth_getBlockByNumber',
        [block1.number, false]);
    check('re-fetch block by number succeeds', !!block2,
        block2 ? `#${block2.number}` : 'null');
    if (block2) {
        check('stateRoot is deterministic across re-fetch',
            hex32Eq(block1.stateRoot, block2.stateRoot),
            `${block1.stateRoot} vs ${block2.stateRoot}`);
        check('transactionsRoot is deterministic across re-fetch',
            hex32Eq(block1.transactionsRoot, block2.transactionsRoot));
        check('receiptsRoot is deterministic across re-fetch',
            hex32Eq(block1.receiptsRoot, block2.receiptsRoot));
        check('block.hash is deterministic across re-fetch',
            hex32Eq(block1.hash, block2.hash),
            `${block1.hash} vs ${block2.hash}`);
    }

    // (c) The stateRoot is a TOS-native cell hash, NOT the Ethereum
    //     empty-trie root, and never all-zero. (See header comment.)
    //     We don't assume the chain is non-empty here in the strong
    //     sense — but the genesis state of TOS EVM is itself a
    //     populated cell (system contracts, fixture accounts), so the
    //     native commitment must differ from both sentinels.
    check('stateRoot is NOT the Ethereum empty-MPT root',
        !hex32Eq(block1.stateRoot, ETHEREUM_EMPTY_MPT_ROOT),
        `${block1.stateRoot}`);
    check('stateRoot is NOT all-zeroes',
        !hex32Eq(block1.stateRoot, ALL_ZERO_32),
        `${block1.stateRoot}`);

    // For completeness, the same negative checks on the other two
    // commitments. transactionsRoot / receiptsRoot ARE allowed to be
    // the all-zero / empty-list commitment for a block with no txs,
    // so we DON'T assert non-zero on those — only that they are
    // deterministic 32-byte hex (already checked above).

    console.log('='.repeat(60));
    console.log(`Results: ${passed} passed, ${failed} failed`);
    process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => { console.error(`Fatal: ${e.message}`); process.exit(1); });
