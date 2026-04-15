/**
 * Live TOS-native intent API integration tests.
 *
 * Tests the permission / intent endpoints that are unique to TOS:
 *   - getAccountCapability
 *   - buildTransactionIntent
 *   - getSigningPayload
 *
 * Automatically skipped when no local node is reachable.
 *
 *   pnpm vitest run --filter client -- --testPathPattern='live-intent'
 */

import { describe, it, expect } from "vitest";
import { TosClient, Networks } from "../index.js";

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

const client = new TosClient({ ...Networks.local, timeout: 5_000, retry: 0 });

async function isNodeUp(): Promise<boolean> {
  try {
    await client.getMasterchainInfo();
    return true;
  } catch {
    return false;
  }
}

const nodeAvailable = await isNodeUp();

// Well-known addresses
const ELECTOR_ADDRESS =
  "-1:3333333333333333333333333333333333333333333333333333333333333333";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe.skipIf(!nodeAvailable)("Intent API live integration", () => {
  // ----- Account capability -----

  it("getAccountCapability() returns AccountCapability", async () => {
    const cap = await client.getAccountCapability(ELECTOR_ADDRESS);
    expect(cap).toBeDefined();
    expect(cap["@type"]).toBe("account.capability");
    expect(cap.address).toBeTruthy();
    expect(typeof cap.account_model).toBe("string");
    expect(typeof cap.authorization_version).toBe("string");
    expect(typeof cap.supports_delegation).toBe("boolean");
    expect(typeof cap.supports_sessions).toBe("boolean");
    expect(typeof cap.supports_agents).toBe("boolean");
    expect(typeof cap.account_state).toBe("string");
    expect(typeof cap.revision).toBe("number");
  });

  // ----- Build transaction intent -----

  it("buildTransactionIntent() returns TransactionIntent", async () => {
    // Use a minimal empty body BOC
    const intent = await client.buildTransactionIntent({
      address: ELECTOR_ADDRESS,
      body: "te6ccgEBAQEAAgAAAA==",  // empty cell as base64 BOC
    });
    expect(intent).toBeDefined();
    expect(intent["@type"]).toBe("transaction.intent");
    expect(intent.from).toBeTruthy();
    expect(typeof intent.account_model).toBe("string");
    expect(typeof intent.authorization_version).toBe("string");
    expect(intent.action).toBeDefined();
    expect(intent.authorization_roles).toBeDefined();
    expect(intent.authorization_roles.signer).toBeTruthy();
    expect(intent.authorization_roles.submitter).toBeTruthy();
  });

  // ----- Signing payload -----

  it("getSigningPayload() returns SigningPayload", async () => {
    const payload = await client.getSigningPayload({
      address: ELECTOR_ADDRESS,
      body: "te6ccgEBAQEAAgAAAA==",
    });
    expect(payload).toBeDefined();
    expect(payload["@type"]).toBe("transaction.signingPayload");
    expect(typeof payload.payload_version).toBe("number");
    expect(typeof payload.payload_encoding).toBe("string");
    expect(typeof payload.payload).toBe("string");
    expect(payload.payload.length).toBeGreaterThan(0);
    expect(typeof payload.chain_id).toBe("number");
  });
});
