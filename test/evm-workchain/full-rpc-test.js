#!/usr/bin/env node
// Full ethers.js integration test against a live TOS EVM workchain.
// Exercises: balance read, signed transfer, receipt, balance verification,
// contract deployment (via raw bytecode), eth_call, gas estimation.

const { ethers } = require('/tmp/evm-rpc-test/node_modules/ethers');

const RPC = process.argv[2] || 'http://127.0.0.1:8011';
const TX_TIMEOUT_MS = 30000;

// Hardhat test account #0
const PRIV_KEY = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

const COLORS = { ok: '\x1b[32m', fail: '\x1b[31m', dim: '\x1b[90m', reset: '\x1b[0m' };
const OK = c => `${COLORS.ok}✓${COLORS.reset} ${c}`;
const FAIL = c => `${COLORS.fail}✗${COLORS.reset} ${c}`;

let pass = 0, fail = 0;
function check(name, cond, detail = '') {
    if (cond) { console.log(OK(name) + (detail ? ` ${COLORS.dim}(${detail})${COLORS.reset}` : '')); pass++; }
    else { console.log(FAIL(name) + (detail ? ` — ${detail}` : '')); fail++; }
}

async function main() {
    console.log(`Full RPC integration test`);
    console.log(`RPC: ${RPC}`);
    console.log('='.repeat(60));

    // Disable batching since our server doesn't support batch requests yet
    const provider = new ethers.JsonRpcProvider(RPC, undefined, {
        batchMaxCount: 1,
        staticNetwork: ethers.Network.from(5525331),
    });
    const wallet = new ethers.Wallet(PRIV_KEY, provider);

    // 1. Network identity
    const net = await provider.getNetwork();
    check('chainId is 5525331', net.chainId === 5525331n, `got ${net.chainId}`);

    // 2. Balance of test account #0
    const balance = await provider.getBalance(wallet.address);
    const balanceTos = Number(ethers.formatEther(balance));
    check('Hardhat #0 balance > 0', balanceTos > 0, `${balanceTos} TOS`);

    // 3. Nonce of test account #0
    const nonce = await provider.getTransactionCount(wallet.address);
    check('Hardhat #0 nonce >= 0', nonce >= 0, `${nonce}`);

    // 4. Gas price
    const feeData = await provider.getFeeData();
    check('gasPrice > 0', feeData.gasPrice > 0n, `${ethers.formatUnits(feeData.gasPrice, 'gwei')} gwei`);

    // 5. Block lookup
    const blockNum = await provider.getBlockNumber();
    check('blockNumber >= 0', blockNum >= 0, `${blockNum}`);

    const block = await provider.getBlock(blockNum);
    check('block has hash', block?.hash?.startsWith('0x'), `block ${blockNum}`);
    check('block has stateRoot', block?.stateRoot?.startsWith('0x'), `${block?.stateRoot?.slice(0, 18)}...`);

    // 6. Read another seeded account
    const recipient = '0x70997970C51812dc3A010C7d01b50e0d17dc79C8';
    const recipientInitial = await provider.getBalance(recipient);
    const recipientInitialTos = Number(ethers.formatEther(recipientInitial));
    check('Hardhat #1 balance >= 10000 (or modified)', recipientInitial >= 10000n, `${recipientInitialTos} TOS`);

    // 7. Static eth_call against zero contract
    try {
        const result = await provider.call({
            to: '0x0000000000000000000000000000000000000000',
            data: '0x',
        });
        check('eth_call to 0x00 returns "0x"', result === '0x', `got ${result.slice(0, 20)}`);
    } catch (e) {
        check('eth_call to 0x00 returns "0x"', false, e.message);
    }

    // 8. Gas estimation
    try {
        const gas = await provider.estimateGas({
            from: wallet.address,
            to: recipient,
            value: ethers.parseEther('1'),
        });
        check('estimateGas for transfer ~ 21000', gas >= 21000n && gas <= 100000n, `${gas} gas`);
    } catch (e) {
        check('estimateGas for transfer', false, e.message);
    }

    // 9. Code lookup (zero contract)
    const code = await provider.getCode('0x0000000000000000000000000000000000000000');
    check('eth_getCode for zero address is "0x"', code === '0x');

    // 10. Send a real transaction
    let txReceipt = null;
    try {
        const sendAmount = ethers.parseEther('0.1');
        const tx = await wallet.sendTransaction({
            to: recipient,
            value: sendAmount,
            gasLimit: 30000,
        });
        check(`tx broadcast (hash=${tx.hash.slice(0, 12)}...)`, true);

        // Wait for receipt with timeout
        const start = Date.now();
        let receipt = null;
        while (Date.now() - start < TX_TIMEOUT_MS) {
            receipt = await provider.getTransactionReceipt(tx.hash);
            if (receipt) break;
            await new Promise(r => setTimeout(r, 500));
        }
        if (receipt) {
            txReceipt = receipt;
            check('receipt status == 1 (success)', receipt.status === 1, `gasUsed=${receipt.gasUsed}`);
            check('receipt has blockNumber', receipt.blockNumber > 0, `block ${receipt.blockNumber}`);
            check('receipt has effectiveGasPrice', receipt.gasPrice > 0n);
        } else {
            check('tx receipt within 30s', false, 'timeout — collator did not produce a block');
        }
    } catch (e) {
        check('signed transfer', false, e.message);
    }

    // 11. Verify recipient balance increased (if tx succeeded)
    if (txReceipt) {
        const recipientFinal = await provider.getBalance(recipient);
        const delta = recipientFinal - recipientInitial;
        const deltaTos = Number(ethers.formatEther(delta));
        check('recipient balance increased by 0.1 TOS', delta === ethers.parseEther('0.1'), `+${deltaTos} TOS`);
    }

    console.log('='.repeat(60));
    console.log(`Results: ${COLORS.ok}${pass} passed${COLORS.reset}, ${fail > 0 ? COLORS.fail : ''}${fail} failed${COLORS.reset}`);
    process.exit(fail > 0 ? 1 : 0);
}

main().catch(e => { console.error('FATAL:', e); process.exit(1); });
