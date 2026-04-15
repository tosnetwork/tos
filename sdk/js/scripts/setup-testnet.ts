/**
 * Initialize the local testnet for SDK integration tests.
 *
 * This script:
 *   1. Reads the genesis wallet key from /data/testnet/state/main-wallet.pk
 *   2. Generates a test wallet from TEST_MNEMONIC (or generates a new one)
 *   3. Funds the test wallet from the genesis account (-1:000...000)
 *   4. Deploys the WalletV4R2 contract for the test wallet
 *   5. Deploys a test Jetton Minter and mints tokens
 *   6. Prints the env vars to add to .env.test
 *
 * Usage:
 *   sudo -E npx tsx scripts/setup-testnet.ts
 *
 * The genesis wallet key requires read access to /data/testnet/state/main-wallet.pk
 * (owned by the tos user), hence sudo.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { TosClient, Networks } from "@tos/client";
import { mnemonicGenerate, mnemonicToPrivateKey, keyPairFromSeed, sign } from "@tos/crypto";
import {
  Address, Cell, beginCell, toNano, hexToBytes, bytesToBase64, contractAddress,
} from "@tos/core";
import { WalletV4R2 } from "@tos/wallets";
import { JETTON_MINTER_CODE_HEX, JETTON_WALLET_CODE_HEX } from "@tos/contracts";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const GENESIS_PK_PATH = "/data/testnet/state/main-wallet.pk";
const GENESIS_ADDRESS = "-1:0000000000000000000000000000000000000000000000000000000000000000";
const FUND_AMOUNT = toNano("10");       // 10 TOS for the test wallet
const MINT_AMOUNT = toNano("1000");     // 1000 test jettons
const CONTENT_URI = "https://example.com/test-jetton.json";

const client = new TosClient({ ...Networks.local, timeout: 10_000 });

// ---------------------------------------------------------------------------
// Genesis wallet helpers (simple wallet v1 at -1:000...000)
// ---------------------------------------------------------------------------

async function genesisSeqno(): Promise<number> {
  const r = await client.rawCall("runGetMethod", {
    address: GENESIS_ADDRESS, method: "seqno", stack: [],
  }) as { stack: [string, string][] };
  return parseInt(r.stack[0]![1]!);
}

async function genesisSend(
  genesisKey: { publicKey: Uint8Array; secretKey: Uint8Array },
  to: Address,
  amount: bigint,
): Promise<void> {
  const seqno = await genesisSeqno();
  const internalMsg = beginCell()
    .storeUint(0x10, 6)           // int_msg_info, no bounce
    .storeAddress(to)
    .storeCoins(amount)
    .storeBit(false).storeCoins(0n).storeCoins(0n)
    .storeUint(0, 64).storeUint(0, 32)
    .storeBit(false).storeBit(false)
    .endCell();

  const sigMsg = beginCell().storeUint(seqno, 32).storeUint(3, 8).storeRef(internalMsg).endCell();
  const sig = sign(sigMsg.hash(), genesisKey.secretKey);
  const body = beginCell()
    .storeBuffer(sig)
    .storeBuilder(beginCell().storeUint(seqno, 32).storeUint(3, 8).storeRef(internalMsg))
    .endCell();

  const genesisAddr = Address.parseRaw(GENESIS_ADDRESS);
  const extMsg = beginCell()
    .storeUint(0b10, 2).storeUint(0b00, 2)
    .storeAddress(genesisAddr).storeCoins(0n)
    .storeBit(false).storeBit(true).storeRef(body)
    .endCell();

  await client.rawCall("sendBoc", { boc: bytesToBase64(extMsg.toBoc()) });
}

// ---------------------------------------------------------------------------
// Wallet external message sender
// ---------------------------------------------------------------------------

async function sendExternal(from: Address, body: Cell): Promise<void> {
  const extMsg = beginCell()
    .storeUint(0b10, 2).storeUint(0b00, 2)
    .storeAddress(from).storeCoins(0n)
    .storeBit(false).storeBit(true).storeRef(body)
    .endCell();
  await client.rawCall("sendBoc", { boc: bytesToBase64(extMsg.toBoc()) });
}

async function walletSeqno(addr: Address): Promise<number> {
  const r = await client.rawCall("runGetMethod", {
    address: addr.toRawString(), method: "seqno", stack: [],
  }) as { stack: [string, string][] };
  return parseInt(r.stack[0]![1]!);
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log("=== TOS SDK Testnet Setup ===\n");

  // 1. Load genesis key
  let genesisKey: { publicKey: Uint8Array; secretKey: Uint8Array };
  try {
    const seed = new Uint8Array(readFileSync(GENESIS_PK_PATH));
    genesisKey = keyPairFromSeed(seed);
    console.log("[1/5] Genesis wallet key loaded from", GENESIS_PK_PATH);
  } catch (e) {
    console.error("ERROR: Cannot read", GENESIS_PK_PATH);
    console.error("  Run with: sudo -E npx tsx scripts/setup-testnet.ts");
    process.exit(1);
  }

  // 2. Generate or load test mnemonic
  let mnemonic = process.env.TEST_MNEMONIC?.split(" ").filter(Boolean);
  let mnemonicGenerated = false;
  if (!mnemonic || mnemonic.length < 12) {
    mnemonic = await mnemonicGenerate(24);
    mnemonicGenerated = true;
    console.log("[2/5] Generated new test mnemonic (24 words)");
  } else {
    console.log("[2/5] Using existing TEST_MNEMONIC from environment");
  }

  const keyPair = await mnemonicToPrivateKey(mnemonic);
  const wallet = WalletV4R2.create({ publicKey: keyPair.publicKey, workchain: 0 });
  const walletAddr = wallet.address;
  console.log("      Wallet address:", walletAddr.toRawString());

  // 3. Fund test wallet from genesis
  console.log("[3/5] Funding test wallet with", FUND_AMOUNT / 1_000_000_000n, "TOS...");
  await genesisSend(genesisKey, walletAddr, FUND_AMOUNT);
  await sleep(5000);

  const balResult = await client.rawCall("getAddressBalance", {
    address: walletAddr.toRawString(),
  }) as string;
  console.log("      Balance:", balResult, "nanoTOS");

  // 4. Deploy WalletV4R2
  const info = await client.rawCall("getAddressInformation", {
    address: walletAddr.toRawString(),
  }) as { state: string };

  if (info.state === "active") {
    console.log("[4/5] Wallet already deployed (active)");
  } else {
    console.log("[4/5] Deploying WalletV4R2...");
    const deployTransfer = wallet.createTransfer({
      seqno: 0,
      secretKey: keyPair.secretKey,
      messages: [{ to: walletAddr, value: toNano("0.05"), bounce: false }],
    });

    const stateInit = beginCell()
      .storeUint(0, 2).storeBit(true).storeRef(wallet.init!.code)
      .storeBit(true).storeRef(wallet.init!.data).storeBit(false)
      .endCell();

    const extMsg = beginCell()
      .storeUint(0b10, 2).storeUint(0b00, 2)
      .storeAddress(walletAddr).storeCoins(0n)
      .storeBit(true).storeBit(true).storeRef(stateInit)
      .storeBit(true).storeRef(deployTransfer)
      .endCell();

    await client.rawCall("sendBoc", { boc: bytesToBase64(extMsg.toBoc()) });
    await sleep(6000);

    const info2 = await client.rawCall("getAddressInformation", {
      address: walletAddr.toRawString(),
    }) as { state: string };
    console.log("      Wallet state:", info2.state);
  }

  // 5. Deploy Jetton Minter + Mint
  console.log("[5/5] Deploying Jetton Minter and minting tokens...");
  const minterCode = Cell.fromBoc(hexToBytes(JETTON_MINTER_CODE_HEX))[0]!;
  const walletCode = Cell.fromBoc(hexToBytes(JETTON_WALLET_CODE_HEX))[0]!;

  const contentCell = beginCell()
    .storeUint(0x01, 8).storeStringTail(CONTENT_URI).endCell();

  const minterData = beginCell()
    .storeCoins(0n).storeAddress(walletAddr)
    .storeRef(contentCell).storeRef(walletCode).endCell();

  const minterAddr = contractAddress(0, { code: minterCode, data: minterData });
  console.log("      Minter address:", minterAddr.toRawString());

  // Deploy minter
  const seqno1 = await walletSeqno(walletAddr);
  const deployMinter = wallet.createTransfer({
    seqno: seqno1, secretKey: keyPair.secretKey,
    messages: [{
      to: minterAddr, value: toNano("0.5"), bounce: false,
      init: { code: minterCode, data: minterData },
    }],
  });
  await sendExternal(walletAddr, deployMinter);
  await sleep(6000);

  // Mint
  const seqno2 = await walletSeqno(walletAddr);
  const mintBody = beginCell()
    .storeUint(21, 32).storeUint(0, 64)
    .storeAddress(walletAddr).storeCoins(toNano("0.5"))
    .storeRef(beginCell()
      .storeUint(0x178d4519, 32).storeUint(0, 64)
      .storeCoins(MINT_AMOUNT)
      .storeAddress(null).storeAddress(walletAddr)
      .storeCoins(toNano("0.01")).storeBit(false).endCell())
    .endCell();

  const mintTransfer = wallet.createTransfer({
    seqno: seqno2, secretKey: keyPair.secretKey,
    messages: [{ to: minterAddr, value: toNano("1"), body: mintBody, bounce: true }],
  });
  await sendExternal(walletAddr, mintTransfer);
  await sleep(8000);

  // Verify
  const minterInfo = await client.rawCall("getAddressInformation", {
    address: minterAddr.toRawString(),
  }) as { state: string };
  console.log("      Minter state:", minterInfo.state);

  // ---------------------------------------------------------------------------
  // Output
  // ---------------------------------------------------------------------------

  const envContent = [
    "# =============================================================================",
    "# TOS JS SDK — Test Environment Variables",
    "#",
    "# AUTO-GENERATED by scripts/setup-testnet.ts",
    "# These wallets are funded from the genesis account of the local testnet.",
    "# DO NOT use these mnemonics on mainnet or any public network.",
    "# =============================================================================",
    "",
    `# WalletV4R2 test wallet (funded with ${Number(FUND_AMOUNT) / 1e9} TOS)`,
    `# Address: ${walletAddr.toRawString()}`,
    `TEST_MNEMONIC="${mnemonic.join(" ")}"`,
    "",
    "# Jetton minter address (TEP-74 standard, deployed on local testnet)",
    `# ${MINT_AMOUNT / 1_000_000_000n} test jettons minted to the wallet above`,
    `TEST_JETTON_MINTER="${minterAddr.toRawString()}"`,
    "",
  ].join("\n");

  const envPath = resolve(__dirname, "../.env.test");
  writeFileSync(envPath, envContent, "utf-8");

  console.log("\n=== Setup complete ===");
  console.log("Written to:", envPath);
  if (mnemonicGenerated) {
    console.log("\nMnemonic (save this):");
    console.log(" ", mnemonic.join(" "));
  }
}

main().catch((e) => { console.error("Fatal:", e.message); process.exit(1); });
