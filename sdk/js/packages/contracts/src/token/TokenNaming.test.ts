import { describe, expect, it, vi } from "vitest";
import { Address, beginCell, Cell, hexToBytes } from "@tos/core";
import type { ContractProvider } from "@tos/client";
import { TokenMaster, TokenWallet, TOKEN_MASTER_CODE_HEX, TOKEN_WALLET_CODE_HEX } from "../index";

const owner = new Address(0, new Uint8Array(32));

function provider() {
  const content = beginCell().storeUint(1, 8).storeStringTail("https://example.invalid/token.json").endCell();
  const get = vi.fn(async (method: string) => {
    if (!["get_token_data", "get_wallet_data", "get_wallet_address"].includes(method)) {
      throw new Error(`Unexpected Token getter: ${method}`);
    }
    return {
      gasUsed: 0,
      exitCode: 0,
      stack: {
        readBigNumber: () => 17n,
        readBoolean: () => true,
        readAddress: () => owner,
        readCell: () => content,
      },
    };
  });
  return { get, contract: { get } as unknown as ContractProvider };
}

describe("Token public API", () => {
  it("exports deployable master and wallet BOCs under their new names", () => {
    for (const hex of [TOKEN_MASTER_CODE_HEX, TOKEN_WALLET_CODE_HEX]) {
      const cells = Cell.fromBoc(hexToBytes(hex));
      expect(cells).toHaveLength(1);
      expect(cells[0]).toBeInstanceOf(Cell);
    }
  });

  it("uses the new getter for supply, administrator and full data", async () => {
    const mock = provider();
    const master = TokenMaster.create(owner);
    expect(await master.getTotalSupply(mock.contract)).toBe(17n);
    expect(await master.getAdminAddress(mock.contract)).toEqual(owner);
    const data = await master.getTokenData(mock.contract);
    expect(data.totalSupply).toBe(17n);
    expect(data.mintable).toBe(true);
    expect(mock.get.mock.calls.map(([method]) => method)).toEqual([
      "get_token_data", "get_token_data", "get_token_data",
    ]);
  });

  it("keeps generic wallet discovery and per-owner balance semantics", async () => {
    const mock = provider();
    expect(await TokenMaster.create(owner).getTokenWalletAddress(mock.contract, owner)).toEqual(owner);
    expect(await TokenWallet.create(owner).getBalance(mock.contract)).toBe(17n);
    expect(mock.get.mock.calls.map(([method]) => method)).toEqual([
      "get_wallet_address", "get_wallet_data",
    ]);
  });
});
