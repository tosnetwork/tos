#!/usr/bin/env node
/*
  proof-receipt-survives-restart — Phase F.5 + F.6 e2e.

  Send mode: broadcasts a tx, waits for receipt, captures hash + block info,
  prints a `--verify` line callers can re-run after a validator restart.

  Verify mode (Phase F.6 extended): re-queries the receipt AND the matching
  transaction (eth_getTransactionByHash), block-by-hash, block-by-number,
  and eth_getLogs(blockHash) — asserts every endpoint returns the expected
  pre-restart values.

  Backward-compat: if invoked as `--verify <hash>` (Phase F.5 form, no extra
  args), it falls back to the receipt-only check; the F.6 form is
  `--verify <txHash> <blockNumber> <blockHash>`.
*/
const { ethers } = require('/tmp/evm-rpc-test/node_modules/ethers');
const URL = process.env.RPC || 'http://127.0.0.1:8011';
const PK = '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

(async () => {
  const provider = new ethers.JsonRpcProvider(URL, undefined, {
    batchMaxCount: 1,
    staticNetwork: ethers.Network.from(5525331),
  });
  const args = process.argv.slice(2);

  if (args[0] === '--verify' && args[1]) {
    const txHash = args[1];
    const expectedBlock = args[2] != null ? Number(args[2]) : null;
    const expectedBlockHash = args[3] || null;

    let allPass = true;
    const fail = (msg) => { console.log(`FAIL: ${msg}`); allPass = false; };

    // 1) receipt
    const r = await provider.getTransactionReceipt(txHash);
    if (!r) {
      console.log(`FAIL: receipt for ${txHash} returned null after restart`);
      process.exit(1);
    }
    console.log(`PASS: receipt survived restart`);
    console.log(`  hash: ${txHash}`);
    console.log(`  block: ${r.blockNumber}`);
    console.log(`  status: ${r.status}`);
    console.log(`  gasUsed: ${r.gasUsed}`);

    // F.6 checks (only if caller passed the extended args).
    if (expectedBlock == null) {
      console.log(`(F.6 verify args missing — pass blockNumber and blockHash to also check tx/block/logs)`);
      process.exit(0);
    }

    // 2) transaction
    const t = await provider.getTransaction(txHash);
    if (!t) {
      fail(`transaction for ${txHash} returned null after restart`);
    } else if (Number(t.blockNumber) !== expectedBlock) {
      fail(`tx blockNumber mismatch: got ${t.blockNumber}, want ${expectedBlock}`);
    } else {
      console.log(`PASS: transaction survived restart (blockNumber=${t.blockNumber})`);
    }

    // 3) block-by-number
    const bN = await provider.send('eth_getBlockByNumber',
        ['0x' + expectedBlock.toString(16), false]);
    if (!bN) {
      fail(`getBlockByNumber(${expectedBlock}) returned null after restart`);
    } else if (expectedBlockHash && bN.hash !== expectedBlockHash) {
      fail(`block-by-number hash mismatch: got ${bN.hash}, want ${expectedBlockHash}`);
    } else {
      console.log(`PASS: block-by-number survived restart (hash=${bN.hash})`);
    }

    // 4) block-by-hash
    if (expectedBlockHash) {
      const bH = await provider.send('eth_getBlockByHash', [expectedBlockHash, false]);
      if (!bH) {
        fail(`getBlockByHash(${expectedBlockHash}) returned null after restart`);
      } else if (Number(bH.number) !== expectedBlock) {
        fail(`block-by-hash number mismatch: got ${bH.number}, want ${expectedBlock}`);
      } else {
        console.log(`PASS: block-by-hash survived restart (number=${bH.number})`);
      }
    }

    // 5) getLogs over the block (always succeeds — empty list is valid for
    //    plain value-transfer txs, which is what this script sends).
    const logs = await provider.send('eth_getLogs', [{
      fromBlock: '0x' + expectedBlock.toString(16),
      toBlock: '0x' + expectedBlock.toString(16),
    }]);
    if (logs == null) {
      fail(`getLogs returned null for block ${expectedBlock}`);
    } else {
      console.log(`PASS: getLogs survived restart (count=${logs.length})`);
    }

    process.exit(allPass ? 0 : 1);
  }

  // Send mode: broadcast and wait for receipt.
  const wallet = new ethers.Wallet(PK, provider);
  const tx = await wallet.sendTransaction({
    to: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8',
    value: ethers.parseEther('0.0' + (Math.floor(Math.random() * 89) + 11)),
    gasLimit: 30000,
  });
  console.log(`TX_HASH=${tx.hash}`);

  let r = null;
  for (let i = 0; i < 60 && !r; i++) {
    await new Promise(s => setTimeout(s, 500));
    r = await provider.getTransactionReceipt(tx.hash);
  }
  if (!r) {
    console.log('FAIL: no receipt after 30s');
    process.exit(1);
  }
  console.log(`RECEIPT_BLOCK=${r.blockNumber}`);
  console.log(`RECEIPT_BLOCK_HASH=${r.blockHash}`);
  console.log(`RECEIPT_STATUS=${r.status}`);
  console.log(`RECEIPT_GAS=${r.gasUsed}`);
  console.log(`OK: tx mined; restart validator and re-run with `
              + `--verify ${tx.hash} ${r.blockNumber} ${r.blockHash}`);
})().catch(e => {
  console.error('FATAL:', e.message);
  process.exit(1);
});
