/**
 * Live wallet integration test -- creates, signs, and submits a transfer
 * on the local TOS node.
 *
 * Prerequisites:
 *   - A local TOS node running at http://localhost:8081
 *   - A funded wallet whose 24-word mnemonic is set in the TEST_MNEMONIC
 *     environment variable (space-separated).
 *
 * When either prerequisite is missing the entire suite is skipped.
 *
 *   TEST_MNEMONIC="word1 word2 ... word24" pnpm vitest run -- --testPathPattern='live-wallet'
 */

import { describe, it, expect, beforeAll } from "vitest";
import { TosClient, Networks, open, waitForSeqnoChange } from "../index.js";

// Cross-package imports via relative paths (workspace packages are not
// declared as dependencies of @tos/client, so bare specifiers don't resolve
// in Vite's module graph).
import { mnemonicToPrivateKey } from "../../../crypto/src/index.js";
import { WalletV4R2, KeyPairSigner } from "../../../wallets/src/index.js";
import { toNano } from "../../../core/src/index.js";

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

const client = new TosClient({ ...Networks.local, timeout: 10_000, retry: 1 });

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
const canRun = nodeAvailable && !!mnemonic && mnemonic.length >= 12;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe.skipIf(!canRun)("Wallet live integration", () => {
  // Use `any` for opened contract types -- the private-constructor constraint
  // on WalletV4R2 prevents clean generic typing with OpenedContract<>.
  let keyPair: Awaited<ReturnType<typeof mnemonicToPrivateKey>>;
  let wallet: ReturnType<typeof WalletV4R2.create>;
  let openedWallet: any;
  let signer: InstanceType<typeof KeyPairSigner>;

  beforeAll(async () => {
    // Derive key pair from mnemonic
    keyPair = await mnemonicToPrivateKey(mnemonic!);

    // Create wallet contract instance
    wallet = WalletV4R2.create({ publicKey: keyPair.publicKey });

    // Open it against the live client
    openedWallet = open(wallet as any, client);

    // Create signer
    signer = new KeyPairSigner(keyPair, openedWallet);
  });

  it("derives a deterministic wallet address", () => {
    expect(wallet.address).toBeDefined();
    expect(wallet.address.toRawString()).toMatch(/^0:/);
  });

  it("getSeqno() returns a non-negative number", async () => {
    const seqno: number = await openedWallet.getSeqno();
    expect(typeof seqno).toBe("number");
    expect(seqno).toBeGreaterThanOrEqual(0);
  });

  it("getBalance() returns a bigint >= 0", async () => {
    const balance: bigint = await openedWallet.getBalance();
    expect(typeof balance).toBe("bigint");
    expect(balance >= 0n).toBe(true);
  });

  it("sends a self-transfer and waits for seqno change", async () => {
    const balance: bigint = await openedWallet.getBalance();
    // Need at least 0.1 TOS to cover fees
    if (balance < toNano("0.1")) {
      console.warn(
        `Skipping self-transfer: balance ${balance} too low (need >= 0.1 TOS)`,
      );
      return;
    }

    const seqnoBefore: number = await openedWallet.getSeqno();

    // Send a tiny self-transfer (0.01 TOS to own address)
    await openedWallet.sendTransfer(signer, {
      messages: [
        {
          to: wallet.address,
          value: toNano("0.01"),
          bounce: false,
        },
      ],
    });

    // Wait for seqno to increment (confirms the tx landed)
    const newSeqno = await waitForSeqnoChange(
      client,
      wallet.address.toRawString(),
      seqnoBefore,
      { timeout: 30_000, pollInterval: 1_500 },
    );

    expect(newSeqno).toBe(seqnoBefore + 1);
  });
});
