import { describe, expect, it, vi } from "vitest";
import { readFileSync } from "node:fs";
import { Address, beginCell, Cell, hexToBytes } from "@tos/core";
import type { ContractProvider } from "@tos/client";
import {
  TokenMaster, TokenWallet, TOKEN_MASTER_CODE_HEX, TOKEN_WALLET_CODE_HEX,
  TOKEN_MINT_MIN_WALLET_VALUE, TOKEN_MINT_MINTER_RESERVE,
} from "../index";

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
  it("produces the messages executed by the native SDK sandbox", async () => {
    const fixture = JSON.parse(readFileSync(new URL(
      "../../../../../../test/fixtures/token-sdk.json", import.meta.url,
    ), "utf8"));
    const bodies: string[] = [];
    const values: bigint[] = [];
    const contract = { internal: async (_via: unknown, args: { body: Cell; value: bigint }) => {
      bodies.push(args.body.toHex());
      values.push(args.value);
    } } as unknown as ContractProvider;
    const master = TokenMaster.create(Address.parse(fixture.admin));
    const signer = {} as Parameters<TokenMaster["sendMint"]>[1];
    await master.sendMint(contract, signer, {
      to: Address.parse(fixture.owner), amount: 17n, walletValue: 200000000n, value: 1000000000n, queryId: 7n,
    });
    // The least funding the SDK accepts; the native sandbox runs it to a new wallet.
    await master.sendMint(contract, signer, {
      to: Address.parse(fixture.owner),
      amount: 17n,
      walletValue: TOKEN_MINT_MIN_WALLET_VALUE,
      value: TOKEN_MINT_MIN_WALLET_VALUE + TOKEN_MINT_MINTER_RESERVE,
      queryId: 9n,
    });
    await master.sendChangeAdmin(contract, signer, Address.parse(fixture.newAdmin), { queryId: 8n });
    expect(bodies).toEqual([fixture.mint, fixture.mintAtFloor, fixture.changeAdmin]);
    expect(values[1]).toBe(BigInt(fixture.mintAtFloorValue));
  });

  it("refuses mints below the funding floors before signing", async () => {
    const internal = vi.fn();
    const contract = { internal } as unknown as ContractProvider;
    const master = TokenMaster.create(owner);
    const signer = {} as Parameters<TokenMaster["sendMint"]>[1];
    const floor = { to: owner, amount: 17n, walletValue: TOKEN_MINT_MIN_WALLET_VALUE,
      value: TOKEN_MINT_MIN_WALLET_VALUE + TOKEN_MINT_MINTER_RESERVE };
    await expect(master.sendMint(contract, signer, { ...floor, amount: 0n })).rejects.toThrow(RangeError);
    await expect(master.sendMint(contract, signer, { ...floor, walletValue: floor.walletValue - 1n }))
      .rejects.toThrow(RangeError);
    await expect(master.sendMint(contract, signer, { ...floor, value: floor.value - 1n }))
      .rejects.toThrow(RangeError);
    expect(internal).not.toHaveBeenCalled();
    await master.sendMint(contract, signer, floor);
    expect(internal).toHaveBeenCalledTimes(1);
  });

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
