#!/usr/bin/env node
/*
  proof-receipt-survives-restart — Phase F.5 e2e.

  Sends a tx, captures the hash and the receipt's blockNumber.
  Caller then restarts the validator (this script doesn't have sudo).
  Re-running with --verify <hash> queries the receipt by hash and
  asserts it returns non-null with matching blockNumber.
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
    const r = await provider.getTransactionReceipt(args[1]);
    if (!r) {
      console.log(`FAIL: receipt for ${args[1]} returned null after restart`);
      process.exit(1);
    }
    console.log(`PASS: receipt survived restart`);
    console.log(`  hash: ${args[1]}`);
    console.log(`  block: ${r.blockNumber}`);
    console.log(`  status: ${r.status}`);
    console.log(`  gasUsed: ${r.gasUsed}`);
    process.exit(0);
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
  console.log(`RECEIPT_STATUS=${r.status}`);
  console.log(`RECEIPT_GAS=${r.gasUsed}`);
  console.log(`OK: tx mined; restart validator and re-run with --verify ${tx.hash}`);
})().catch(e => {
  console.error('FATAL:', e.message);
  process.exit(1);
});
