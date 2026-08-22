/** TOS account addresses: raw `wc:hex` and user-friendly base64url forms. */
import { Builder, bytesToHex, hexToBytes, Slice } from './cell.js';

export interface RawAddress {
  workchain: number;
  hash: Uint8Array; // 32 bytes
}

export function parseRawAddress(s: string): RawAddress {
  const m = /^(-?\d+):([0-9a-fA-F]{64})$/.exec(s.trim());
  if (!m) {
    throw new Error(`invalid raw address: ${s}`);
  }
  const workchain = Number(m[1]);
  if (workchain < -128 || workchain > 127) {
    throw new Error('workchain out of addr_std range');
  }
  return { workchain, hash: hexToBytes(m[2] as string) };
}

export function formatRawAddress(a: RawAddress): string {
  return `${a.workchain}:${bytesToHex(a.hash)}`;
}

/** Store addr_std$10 anycast:nothing wc:int8 addr:bits256. */
export function storeAddress(b: Builder, a: RawAddress): Builder {
  b.storeBits('100');
  b.storeInt(a.workchain, 8);
  b.storeBytes(a.hash);
  return b;
}

/** Load an addr_std; rejects every other MsgAddress constructor. */
export function loadAddress(s: Slice): RawAddress {
  const tag = Number(s.loadUint(2));
  if (tag !== 2) {
    throw new Error('expected addr_std');
  }
  if (s.loadBit() !== 0) {
    throw new Error('anycast addresses are not supported');
  }
  let workchain = Number(s.loadUint(8));
  if (workchain > 127) {
    workchain -= 256;
  }
  return { workchain, hash: s.loadBytes(32) };
}

const CRC16_POLY = 0x1021; // CCITT / XModem, as used by friendly addresses

function crc16(data: Uint8Array): number {
  let crc = 0;
  for (const byte of data) {
    crc ^= byte << 8;
    for (let i = 0; i < 8; i++) {
      crc = crc & 0x8000 ? ((crc << 1) ^ CRC16_POLY) & 0xffff : (crc << 1) & 0xffff;
    }
  }
  return crc;
}

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export function formatFriendlyAddress(
  a: RawAddress,
  opts: { bounceable?: boolean; testOnly?: boolean } = {},
): string {
  const bounceable = opts.bounceable ?? true;
  let tag = bounceable ? 0x11 : 0x51;
  if (opts.testOnly) {
    tag |= 0x80;
  }
  const payload = new Uint8Array(36);
  payload[0] = tag;
  payload[1] = a.workchain & 0xff;
  payload.set(a.hash, 2);
  const crc = crc16(payload.subarray(0, 34));
  payload[34] = crc >> 8;
  payload[35] = crc & 0xff;
  let out = '';
  for (let i = 0; i < 36; i += 3) {
    const n =
      ((payload[i] as number) << 16) | ((payload[i + 1] as number) << 8) | (payload[i + 2] as number);
    out +=
      (B64URL[(n >> 18) & 63] as string) +
      (B64URL[(n >> 12) & 63] as string) +
      (B64URL[(n >> 6) & 63] as string) +
      (B64URL[n & 63] as string);
  }
  return out;
}
