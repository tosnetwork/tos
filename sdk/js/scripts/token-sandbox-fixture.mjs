// Public SDK messages shared with the native sandbox. No network or signer.
import { Address, beginCell, Cell, hexToBytes } from '../packages/core/dist/index.js';
import {
  TokenMaster, TOKEN_WALLET_CODE_HEX, TOKEN_MINT_MIN_WALLET_VALUE, TOKEN_MINT_MINTER_RESERVE,
} from '../packages/contracts/dist/index.js';
import { writeFileSync } from 'node:fs';

const address = (value) => new Address(0, new Uint8Array(32).fill(value));
const admin = address(0x11), owner = address(0x22), newAdmin = address(0x33);
const messages = {};
const provider = { internal: async (_via, args) => {
  messages.body = args.body.toHex();
  messages.value = args.value;
} };
const master = TokenMaster.create(address(0x44));
await master.sendMint(provider, {}, {
  to: owner, amount: 17n, walletValue: 200000000n, value: 1000000000n, queryId: 7n,
});
const mint = messages.body;
// The least funding the SDK accepts.
await master.sendMint(provider, {}, {
  to: owner, amount: 17n, walletValue: TOKEN_MINT_MIN_WALLET_VALUE,
  value: TOKEN_MINT_MIN_WALLET_VALUE + TOKEN_MINT_MINTER_RESERVE, queryId: 9n,
});
const mintAtFloor = messages.body, mintAtFloorValue = messages.value.toString();
await master.sendChangeAdmin(provider, {}, newAdmin, { queryId: 8n });
const wallet = Cell.fromBoc(hexToBytes(TOKEN_WALLET_CODE_HEX))[0];
const data = beginCell().storeCoins(0n).storeAddress(admin)
  .storeRef(beginCell().storeUint(1, 8).storeStringTail('https://example.invalid/token.json').endCell())
  .storeRef(wallet).endCell();
writeFileSync(new URL('../../../test/fixtures/token-sdk.json', import.meta.url), JSON.stringify({
  admin: admin.toRawString(), owner: owner.toRawString(), newAdmin: newAdmin.toRawString(),
  data: data.toHex(), mint, mintAtFloor, mintAtFloorValue, changeAdmin: messages.body,
}, null, 2) + '\n');
