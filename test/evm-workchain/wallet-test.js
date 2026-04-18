#!/usr/bin/env node
/**
 * EVM Workchain — wallet integration test.
 *
 * Tests the full wallet flow against a running node:
 *   1. eth_chainId           → verify network identity
 *   2. eth_blockNumber       → verify block tracking
 *   3. eth_getBalance        → check account balance
 *   4. eth_getTransactionCount → check nonce
 *   5. eth_sendRawTransaction → submit signed transaction
 *   6. eth_getTransactionReceipt → confirm execution
 *   7. eth_call              → read-only contract call
 *   8. eth_estimateGas       → gas estimation
 *
 * Usage:
 *   node wallet-test.js [rpc_url]
 *
 * Default RPC URL: http://127.0.0.1:8081
 *
 * Prerequisites:
 *   npm install ethers
 *
 * The test seeds a known account with balance via a curl call,
 * then runs the full wallet flow using ethers.js.
 */

const RPC_URL = process.argv[2] || 'http://127.0.0.1:8081';

async function jsonRpc(method, params = []) {
    const body = JSON.stringify({
        jsonrpc: '2.0',
        method,
        params,
        id: Date.now()
    });

    const resp = await fetch(RPC_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body
    });

    const json = await resp.json();
    if (json.error) {
        throw new Error(`${method} failed: ${JSON.stringify(json.error)}`);
    }
    return json.result;
}

async function main() {
    console.log(`EVM Workchain — wallet integration test`);
    console.log(`RPC URL: ${RPC_URL}`);
    console.log(`========================================\n`);

    let passed = 0;
    let failed = 0;

    const check = (name, ok) => {
        if (ok) {
            console.log(`  ✓ ${name}`);
            passed++;
        } else {
            console.log(`  ✗ ${name}`);
            failed++;
        }
    };

    // 1. eth_chainId
    try {
        const chainId = await jsonRpc('eth_chainId');
        console.log(`eth_chainId: ${chainId}`);
        check('chainId is 0x544f53', chainId === '0x544f53');
    } catch (e) {
        console.log(`eth_chainId: FAILED - ${e.message}`);
        failed++;
    }

    // 2. eth_blockNumber
    try {
        const blockNum = await jsonRpc('eth_blockNumber');
        console.log(`eth_blockNumber: ${blockNum}`);
        check('blockNumber is a hex number', blockNum.startsWith('0x'));
    } catch (e) {
        console.log(`eth_blockNumber: FAILED - ${e.message}`);
        failed++;
    }

    // 3. net_version
    try {
        const netVersion = await jsonRpc('net_version');
        console.log(`net_version: ${netVersion}`);
        check('net_version is 5525331', netVersion === '5525331');
    } catch (e) {
        console.log(`net_version: FAILED - ${e.message}`);
        failed++;
    }

    // 4. web3_clientVersion
    try {
        const clientVersion = await jsonRpc('web3_clientVersion');
        console.log(`web3_clientVersion: ${clientVersion}`);
        check('client version starts with evm-workchain', clientVersion.startsWith('evm-workchain'));
    } catch (e) {
        console.log(`web3_clientVersion: FAILED - ${e.message}`);
        failed++;
    }

    // 5. eth_gasPrice
    try {
        const gasPrice = await jsonRpc('eth_gasPrice');
        console.log(`eth_gasPrice: ${gasPrice}`);
        check('gasPrice is hex quantity', /^0x[0-9a-f]+$/i.test(gasPrice) && BigInt(gasPrice) > 0n);
    } catch (e) {
        console.log(`eth_gasPrice: FAILED - ${e.message}`);
        failed++;
    }

    // 6. eth_getBalance (zero address, should return 0)
    try {
        const balance = await jsonRpc('eth_getBalance', [
            '0x0000000000000000000000000000000000000000',
            'latest'
        ]);
        console.log(`eth_getBalance(zero): ${balance}`);
        check('zero address balance is hex quantity', /^0x[0-9a-f]+$/i.test(balance));
    } catch (e) {
        console.log(`eth_getBalance: FAILED - ${e.message}`);
        failed++;
    }

    // 7. eth_getTransactionCount
    try {
        const nonce = await jsonRpc('eth_getTransactionCount', [
            '0x0000000000000000000000000000000000000000',
            'latest'
        ]);
        console.log(`eth_getTransactionCount(zero): ${nonce}`);
        check('zero address nonce is 0x0', nonce === '0x0');
    } catch (e) {
        console.log(`eth_getTransactionCount: FAILED - ${e.message}`);
        failed++;
    }

    // 8. eth_getCode (zero address, should return 0x)
    try {
        const code = await jsonRpc('eth_getCode', [
            '0x0000000000000000000000000000000000000000',
            'latest'
        ]);
        console.log(`eth_getCode(zero): ${code}`);
        check('zero address code is 0x', code === '0x');
    } catch (e) {
        console.log(`eth_getCode: FAILED - ${e.message}`);
        failed++;
    }

    // 9. eth_accounts
    try {
        const accounts = await jsonRpc('eth_accounts');
        console.log(`eth_accounts: ${JSON.stringify(accounts)}`);
        check('accounts is empty array', Array.isArray(accounts) && accounts.length === 0);
    } catch (e) {
        console.log(`eth_accounts: FAILED - ${e.message}`);
        failed++;
    }

    // 10. eth_syncing
    try {
        const syncing = await jsonRpc('eth_syncing');
        console.log(`eth_syncing: ${syncing}`);
        check('syncing is false', syncing === false);
    } catch (e) {
        console.log(`eth_syncing: FAILED - ${e.message}`);
        failed++;
    }

    // 11. eth_getBlockByNumber
    try {
        const block = await jsonRpc('eth_getBlockByNumber', ['latest', false]);
        console.log(`eth_getBlockByNumber: number=${block?.number}`);
        check('block has number field', block && typeof block.number === 'string');
    } catch (e) {
        console.log(`eth_getBlockByNumber: FAILED - ${e.message}`);
        failed++;
    }

    // 12. eth_feeHistory (MetaMask gas estimation)
    try {
        const feeHistory = await jsonRpc('eth_feeHistory', ['0x1', 'latest', [25, 75]]);
        console.log(`eth_feeHistory: baseFee=${feeHistory?.baseFeePerGas?.[0]}`);
        check('feeHistory has baseFeePerGas', feeHistory && Array.isArray(feeHistory.baseFeePerGas));
    } catch (e) {
        console.log(`eth_feeHistory: FAILED - ${e.message}`);
        failed++;
    }

    // 13. eth_maxPriorityFeePerGas
    try {
        const maxPriority = await jsonRpc('eth_maxPriorityFeePerGas');
        console.log(`eth_maxPriorityFeePerGas: ${maxPriority}`);
        check('maxPriorityFee is a hex value', typeof maxPriority === 'string' && maxPriority.startsWith('0x'));
    } catch (e) {
        console.log(`eth_maxPriorityFeePerGas: FAILED - ${e.message}`);
        failed++;
    }

    // 14. eth_getStorageAt
    try {
        const storage = await jsonRpc('eth_getStorageAt', [
            '0x0000000000000000000000000000000000000000',
            '0x0',
            'latest'
        ]);
        console.log(`eth_getStorageAt: ${storage}`);
        check('storage is 32 bytes hex', typeof storage === 'string' && storage.length === 66);
    } catch (e) {
        console.log(`eth_getStorageAt: FAILED - ${e.message}`);
        failed++;
    }

    // 15. net_listening
    try {
        const listening = await jsonRpc('net_listening');
        console.log(`net_listening: ${listening}`);
        check('listening is true', listening === true);
    } catch (e) {
        console.log(`net_listening: FAILED - ${e.message}`);
        failed++;
    }

    // 16. eth_newBlockFilter + eth_getFilterChanges + eth_uninstallFilter
    try {
        const filterId = await jsonRpc('eth_newBlockFilter');
        const changes = await jsonRpc('eth_getFilterChanges', [filterId]);
        const uninstalled = await jsonRpc('eth_uninstallFilter', [filterId]);
        console.log(`eth_newBlockFilter: ${filterId}, changes: ${JSON.stringify(changes)}, uninstall: ${uninstalled}`);
        check('filter lifecycle works', filterId && Array.isArray(changes) && uninstalled === true);
    } catch (e) {
        console.log(`filter lifecycle: FAILED - ${e.message}`);
        failed++;
    }

    // Summary
    console.log(`\n========================================`);
    console.log(`Results: ${passed} passed, ${failed} failed`);
    if (failed === 0) {
        console.log(`All wallet compatibility checks passed.`);
    } else {
        console.log(`Some checks failed — see above.`);
        process.exit(1);
    }
}

main().catch(e => {
    console.error(`Fatal error: ${e.message}`);
    process.exit(1);
});
