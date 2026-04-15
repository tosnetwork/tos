/**
 * Deploy a test Jetton (TEP-74) on the local TOS testnet.
 *
 * This script uses the @tos/sdk packages to:
 *   1. Load the test wallet from TEST_MNEMONIC
 *   2. Deploy a standard Jetton Minter contract
 *   3. Mint tokens to the test wallet
 *   4. Print the minter address for TEST_JETTON_MINTER
 *
 * Usage:
 *   npx tsx scripts/deploy-test-jetton.ts
 *
 * Prerequisites:
 *   - Local TOS node at 127.0.0.1:8011
 *   - TEST_MNEMONIC set (or .env.test with funded wallet)
 */

import { TosClient, Networks } from "@tos/client";
import { mnemonicToPrivateKey } from "@tos/crypto";
import {
  Address, Cell, beginCell, toNano, hexToBytes, bytesToBase64, contractAddress,
} from "@tos/core";
import { WalletV4R2 } from "@tos/wallets";
import { JETTON_MINTER_CODE_HEX, JETTON_WALLET_CODE_HEX } from "@tos/contracts";

// ---------------------------------------------------------------------------

const MINT_AMOUNT = toNano("1000");     // 1000 jettons to mint
const CONTENT_URI = "https://example.com/test-jetton.json";

async function main() {
  // 1. Setup
  const mnemonic = process.env.TEST_MNEMONIC?.split(" ").filter(Boolean);
  if (!mnemonic || mnemonic.length < 12) {
    console.error("ERROR: TEST_MNEMONIC not set. Add it to .env.test or export it.");
    process.exit(1);
  }

  const client = new TosClient({ ...Networks.local, timeout: 10_000 });
  const keyPair = await mnemonicToPrivateKey(mnemonic);
  const wallet = WalletV4R2.create({ publicKey: keyPair.publicKey, workchain: 0 });
  const adminAddr = wallet.address;

  console.log("Admin wallet:", adminAddr.toRawString());

  // 2. Build Jetton Minter code & data
  const minterCode = Cell.fromBoc(hexToBytes(JETTON_MINTER_CODE_HEX))[0]!;
  const walletCode = Cell.fromBoc(hexToBytes(JETTON_WALLET_CODE_HEX))[0]!;

  const contentCell = beginCell()
    .storeUint(0x01, 8)                   // off-chain content prefix
    .storeStringTail(CONTENT_URI)
    .endCell();

  const minterData = beginCell()
    .storeCoins(0n)                       // initial total_supply = 0
    .storeAddress(adminAddr)              // admin
    .storeRef(contentCell)                // jetton_content
    .storeRef(walletCode)                 // jetton_wallet_code
    .endCell();

  const minterAddr = contractAddress(0, { code: minterCode, data: minterData });
  console.log("Jetton Minter will deploy at:", minterAddr.toRawString());

  // 3. Deploy minter via wallet transfer with state_init
  const seqno = await getSeqno(client, adminAddr);
  const deployTransfer = wallet.createTransfer({
    seqno,
    secretKey: keyPair.secretKey,
    messages: [{
      to: minterAddr,
      value: toNano("0.5"),
      bounce: false,
      init: { code: minterCode, data: minterData },
    }],
  });

  await sendExternal(client, adminAddr, deployTransfer);
  console.log("Deploy tx sent, waiting 6s...");
  await sleep(6000);

  const minterInfo = await client.rawCall("getAddressInformation", {
    address: minterAddr.toRawString(),
  }) as { state: string };
  console.log("Minter state:", minterInfo.state);

  if (minterInfo.state !== "active") {
    console.error("ERROR: Minter deployment failed.");
    process.exit(1);
  }

  // 4. Mint tokens
  const seqno2 = await getSeqno(client, adminAddr);
  const mintBody = beginCell()
    .storeUint(21, 32)                    // op: mint
    .storeUint(0, 64)                     // query_id
    .storeAddress(adminAddr)              // destination
    .storeCoins(toNano("0.5"))            // forward_ton_amount
    .storeRef(
      beginCell()
        .storeUint(0x178d4519, 32)        // op: internal_transfer
        .storeUint(0, 64)                 // query_id
        .storeCoins(MINT_AMOUNT)          // jetton_amount
        .storeAddress(null)               // from_address (null = mint)
        .storeAddress(adminAddr)          // response_address
        .storeCoins(toNano("0.01"))       // forward_amount
        .storeBit(false)                  // no forward_payload
        .endCell(),
    )
    .endCell();

  const mintTransfer = wallet.createTransfer({
    seqno: seqno2,
    secretKey: keyPair.secretKey,
    messages: [{
      to: minterAddr,
      value: toNano("1"),
      body: mintBody,
      bounce: true,
    }],
  });

  await sendExternal(client, adminAddr, mintTransfer);
  console.log("Mint tx sent, waiting 8s...");
  await sleep(8000);

  // 5. Verify
  const jettonData = await client.rawCall("runGetMethod", {
    address: minterAddr.toRawString(),
    method: "get_jetton_data",
    stack: [],
  }) as { exit_code: number; stack: [string, string][] };

  if (jettonData.exit_code === 0) {
    const supply = jettonData.stack[jettonData.stack.length - 1]![1];
    console.log("Total supply (raw):", supply);
  }

  console.log("\n=== Jetton Minter deployed successfully ===");
  console.log(`TEST_JETTON_MINTER="${minterAddr.toRawString()}"`);
  console.log("\nAdd this to sdk/js/.env.test to enable Jetton integration tests.");
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function getSeqno(client: TosClient, addr: Address): Promise<number> {
  const result = await client.rawCall("runGetMethod", {
    address: addr.toRawString(), method: "seqno", stack: [],
  }) as { stack: [string, string][] };
  return parseInt(result.stack[0]![1]!);
}

async function sendExternal(client: TosClient, from: Address, body: Cell): Promise<void> {
  const extMsg = beginCell()
    .storeUint(0b10, 2)       // ext_in_msg_info
    .storeUint(0b00, 2)       // src: addr_none
    .storeAddress(from)       // dest
    .storeCoins(0n)           // import_fee
    .storeBit(false)          // no state init
    .storeBit(true)           // body as ref
    .storeRef(body)
    .endCell();

  await client.rawCall("sendBoc", { boc: bytesToBase64(extMsg.toBoc()) });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
main().catch((e) => {
  console.error("Fatal:", e.message);
  process.exit(1);
});
