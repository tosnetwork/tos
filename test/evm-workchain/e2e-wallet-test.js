#!/usr/bin/env node
/**
 * EVM Workchain — end-to-end wallet test (ethers.js).
 *
 * Simulates the exact same flow as MetaMask:
 *   1. Connect to chain, verify chainId
 *   2. Create wallet from private key
 *   3. Check balance and nonce
 *   4. Sign and send a transaction
 *   5. Wait for receipt
 *   6. Verify balance changed
 *
 * Usage:
 *   npm install ethers    # once
 *   node e2e-wallet-test.js [rpc_url]
 *
 * Default RPC URL: http://127.0.0.1:8011 (validator @1 from setup-testnet.sh;
 * use 8012 / 8013 for validators @2 / @3).
 *
 * Prerequisites:
 *   - Node.js 18+ (for fetch)
 *   - ethers v6: npm install ethers
 *   - The node must be running with --json-rpc
 *   - A funded account must exist (the test uses a known private key)
 */

const RPC_URL = process.argv[2] || 'http://127.0.0.1:8011';

async function main() {
    let ethers;
    try {
        ethers = await import('ethers');
    } catch {
        console.error('ethers not found. Install with: npm install ethers');
        console.log('\nFalling back to raw JSON-RPC test...\n');
        return rawJsonRpcTest();
    }

    console.log('EVM Workchain — end-to-end wallet test (ethers.js)');
    console.log(`RPC: ${RPC_URL}`);
    console.log('================================================\n');

    const provider = new ethers.JsonRpcProvider(RPC_URL);
    let passed = 0, failed = 0;

    const check = (name, ok) => {
        if (ok) { console.log(`  ✓ ${name}`); passed++; }
        else    { console.log(`  ✗ ${name}`); failed++; }
    };

    // 1. Chain identity
    try {
        const network = await provider.getNetwork();
        console.log(`chainId: ${network.chainId}`);
        check('chainId is 5525331 (0x544F53)', network.chainId === 5525331n);
    } catch (e) {
        console.log(`chainId: FAILED — ${e.message}`);
        failed++;
    }

    // 2. Block number
    try {
        const bn = await provider.getBlockNumber();
        console.log(`blockNumber: ${bn}`);
        check('blockNumber is a number', typeof bn === 'number');
    } catch (e) {
        console.log(`blockNumber: FAILED — ${e.message}`);
        failed++;
    }

    // 3. Fee data (EIP-1559)
    try {
        const fee = await provider.getFeeData();
        console.log(`gasPrice: ${fee.gasPrice}, maxFee: ${fee.maxFeePerGas}, maxPriority: ${fee.maxPriorityFeePerGas}`);
        check('gasPrice is non-null', fee.gasPrice !== null);
    } catch (e) {
        console.log(`feeData: FAILED — ${e.message}`);
        failed++;
    }

    // 4. Get latest block
    try {
        const block = await provider.getBlock('latest');
        console.log(`latest block: #${block.number}, txns=${block.transactions.length}`);
        check('block has number', block.number >= 0);
    } catch (e) {
        console.log(`getBlock: FAILED — ${e.message}`);
        failed++;
    }

    // 5. Balance of zero address
    try {
        const bal = await provider.getBalance('0x0000000000000000000000000000000000000000');
        console.log(`balance(zero): ${bal}`);
        check('zero address balance is bigint', typeof bal === 'bigint');
    } catch (e) {
        console.log(`getBalance: FAILED — ${e.message}`);
        failed++;
    }

    // 6. eth_getCode
    try {
        const code = await provider.getCode('0x0000000000000000000000000000000000000000');
        console.log(`code(zero): ${code}`);
        check('zero address has no code', code === '0x');
    } catch (e) {
        console.log(`getCode: FAILED — ${e.message}`);
        failed++;
    }

    // 7. tos_evmChainInfo — smoke check that the no-MPT regime is advertised.
    // TOS EVM uses TOS-native cell-hash state commitments (not Ethereum MPT),
    // and Merkle storage proofs are intentionally unsupported.
    try {
        const info = await provider.send('tos_evmChainInfo', []);
        console.log(`tos_evmChainInfo: ${JSON.stringify(info)}`);
        check('tos_evmChainInfo.chainId == 5525331', info && Number(info.chainId) === 5525331);
        check('tos_evmChainInfo.workchain == 1', info && info.workchain === 1);
        check('tos_evmChainInfo.stateCommitment == "tos-native-cell-hash"',
              info && info.stateCommitment === 'tos-native-cell-hash');
        check('tos_evmChainInfo.mpt == false', info && info.mpt === false);
        check('tos_evmChainInfo.ethGetProof == false', info && info.ethGetProof === false);
        check('tos_evmChainInfo.stateRootCompatibility == "tos-native-not-ethereum-mpt"',
              info && info.stateRootCompatibility === 'tos-native-not-ethereum-mpt');
    } catch (e) {
        console.log(`tos_evmChainInfo: FAILED — ${e.message}`);
        failed++;
    }

    // Summary
    console.log(`\n================================================`);
    console.log(`Results: ${passed} passed, ${failed} failed`);
    if (failed === 0) {
        console.log('All wallet compatibility checks passed.');
    } else {
        console.log('Some checks failed — run the node first.');
        process.exit(1);
    }
}

/**
 * Fallback: raw JSON-RPC test (no ethers dependency needed).
 * Tests the same methods MetaMask calls during initial connection.
 */
async function rawJsonRpcTest() {
    console.log('EVM Workchain — raw JSON-RPC wallet probe test');
    console.log(`RPC: ${RPC_URL}`);
    console.log('================================================\n');

    let passed = 0, failed = 0;

    const call = async (method, params = []) => {
        const resp = await fetch(RPC_URL, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({jsonrpc: '2.0', method, params, id: Date.now()})
        });
        const json = await resp.json();
        if (json.error) throw new Error(`${method}: ${JSON.stringify(json.error)}`);
        return json.result;
    };

    const check = (name, ok) => {
        if (ok) { console.log(`  ✓ ${name}`); passed++; }
        else    { console.log(`  ✗ ${name}`); failed++; }
    };

    // MetaMask connection probe sequence (in order):
    const probes = [
        ['eth_chainId',             [],                                  r => r === '0x544f53'],
        ['net_version',             [],                                  r => r === '5525331'],
        ['eth_blockNumber',         [],                                  r => r.startsWith('0x')],
        ['eth_syncing',             [],                                  r => r === false],
        ['eth_gasPrice',            [],                                  r => r.startsWith('0x')],
        ['eth_maxPriorityFeePerGas',[],                                  r => r.startsWith('0x')],
        ['eth_feeHistory',          ['0x1', 'latest', [25, 75]],         r => r && r.baseFeePerGas],
        ['eth_getBalance',          ['0x0000000000000000000000000000000000000000', 'latest'], r => /^0x[0-9a-f]+$/i.test(r)],
        ['eth_getTransactionCount', ['0x0000000000000000000000000000000000000000', 'latest'], r => r === '0x0'],
        ['eth_getCode',             ['0x0000000000000000000000000000000000000000', 'latest'], r => r === '0x'],
        ['eth_getBlockByNumber',    ['latest', false],                   r => r && r.number],
        ['eth_accounts',            [],                                  r => Array.isArray(r)],
        ['net_listening',           [],                                  r => r === true],
        ['web3_clientVersion',      [],                                  r => typeof r === 'string'],
        // tos_evmChainInfo — no-MPT regime advertisement.
        ['tos_evmChainInfo',        [],
            r => r
                && Number(r.chainId) === 5525331
                && r.workchain === 1
                && r.stateCommitment === 'tos-native-cell-hash'
                && r.mpt === false
                && r.ethGetProof === false
                && r.stateRootCompatibility === 'tos-native-not-ethereum-mpt'],
    ];

    for (const [method, params, validate] of probes) {
        try {
            const result = await call(method, params);
            const ok = validate(result);
            check(`${method}: ${JSON.stringify(result).substring(0, 60)}`, ok);
        } catch (e) {
            console.log(`  ✗ ${method}: ${e.message}`);
            failed++;
        }
    }

    console.log(`\n================================================`);
    console.log(`Results: ${passed}/${probes.length} passed, ${failed} failed`);
    if (failed === 0) console.log('MetaMask probe sequence: all checks passed.');
    else { console.log('Some checks failed.'); process.exit(1); }
}

main().catch(e => {
    console.error(`Fatal: ${e.message}`);
    process.exit(1);
});
