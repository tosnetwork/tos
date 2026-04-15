/**
 * Live jetton end-to-end flow test against a local TOS node.
 *
 * Prerequisites:
 *   - A local TOS node running at http://localhost:8081
 *   - TEST_JETTON_MINTER env var set to a deployed JettonMinter raw address
 *   - (optional) TEST_MNEMONIC env var for write operations (transfer)
 *
 * When the node is down or TEST_JETTON_MINTER is missing, the suite is skipped.
 *
 *   TEST_JETTON_MINTER="0:abc...123" TEST_MNEMONIC="word1 ... word24" \
 *     pnpm vitest run -- --testPathPattern='live-jetton'
 */

import { describe, it, expect, beforeAll } from "vitest";
import { TosClient, Networks, open } from "../index.js";

// Cross-package imports via relative paths (workspace packages are not
// declared as dependencies of @tos/client, so bare specifiers don't resolve
// in Vite's module graph).
import { Address, toNano } from "../../../core/src/index.js";
import { JettonMinter, JettonWallet } from "../../../contracts/src/index.js";
import { mnemonicToPrivateKey } from "../../../crypto/src/index.js";
import { WalletV4R2, KeyPairSigner } from "../../../wallets/src/index.js";

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

const client = new TosClient({ ...Networks.local, timeout: 10_000, retry: 1 });

const jettonMinterAddress = process.env.TEST_JETTON_MINTER;
const mnemonic = process.env.TEST_MNEMONIC?.split(" ").filter(Boolean);

async function isNodeUp(): Promise<boolean> {
  try {
    await client.getMasterchainInfo();
    return true;
  } catch {
    return false;
  }
}

const nodeAvailable = await isNodeUp();
const canRun = nodeAvailable && !!jettonMinterAddress;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe.skipIf(!canRun)("Jetton live integration", () => {
  // Use `any` for opened contract types -- private constructors on contract
  // classes prevent clean generic typing with OpenedContract<>.
  let minterAddr: InstanceType<typeof Address>;
  let openedMinter: any;

  beforeAll(() => {
    minterAddr = Address.parse(jettonMinterAddress!);
    const minter = JettonMinter.create(minterAddr);
    openedMinter = open(minter as any, client);
  });

  it("getTotalSupply() returns a bigint >= 0", async () => {
    const supply: bigint = await openedMinter.getTotalSupply();
    expect(typeof supply).toBe("bigint");
    expect(supply >= 0n).toBe(true);
  });

  it("getJettonWalletAddress() returns an Address for a known owner", async () => {
    // Use config address as a dummy owner to resolve a jetton wallet address
    const ownerAddr = Address.parse(
      "-1:5555555555555555555555555555555555555555555555555555555555555555",
    );
    const jettonWalletAddr = await openedMinter.getJettonWalletAddress(ownerAddr);
    expect(jettonWalletAddr).toBeDefined();
    // The returned address should be a valid Address with toRawString()
    expect(typeof jettonWalletAddr.toRawString()).toBe("string");
  });

  describe.skipIf(!mnemonic || mnemonic.length < 12)("Jetton wallet operations (funded wallet)", () => {
    let walletAddress: InstanceType<typeof Address>;
    let openedJettonWallet: any;

    beforeAll(async () => {
      // Derive wallet from mnemonic
      const keyPair = await mnemonicToPrivateKey(mnemonic!);
      const wallet = WalletV4R2.create({ publicKey: keyPair.publicKey });
      walletAddress = wallet.address;

      // Get the jetton wallet address for our owner
      const jettonWalletAddr = await openedMinter.getJettonWalletAddress(walletAddress);
      const jettonWalletContract = JettonWallet.create(jettonWalletAddr);
      openedJettonWallet = open(jettonWalletContract as any, client);
    });

    it("getBalance() on the jetton wallet returns a bigint >= 0", async () => {
      const balance: bigint = await openedJettonWallet.getBalance();
      expect(typeof balance).toBe("bigint");
      expect(balance >= 0n).toBe(true);
    });

    it("sends a small jetton transfer if balance > 0", async () => {
      const balance: bigint = await openedJettonWallet.getBalance();
      if (balance <= 0n) {
        console.warn("Skipping jetton transfer: jetton wallet balance is 0");
        return;
      }

      // Build signer from mnemonic
      const keyPair = await mnemonicToPrivateKey(mnemonic!);
      const wallet = WalletV4R2.create({ publicKey: keyPair.publicKey });
      const openedWallet = open(wallet as any, client);
      const signer = new KeyPairSigner(keyPair, openedWallet as any);

      // Transfer 1 jetton unit back to self
      await openedJettonWallet.sendTransfer(signer, {
        to: walletAddress,
        amount: 1n,
        value: toNano("0.05"),
      });

      // If we got here without throwing, the external message was accepted
      expect(true).toBe(true);
    });
  });
});
