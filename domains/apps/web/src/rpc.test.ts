import { describe, expect, it } from 'vitest';
import { Builder, bytesToBase64, parseRawAddress, serializeBoc, storeAddress } from '@tos-domains/protocol';
import { sameCheckpoint, stackAddress, stackBigInt, stackNumber } from './rpc.js';

describe('strict JSON-RPC stack parsing', () => {
  it('accepts named and compact TVM numbers', () => {
    expect(stackBigInt(['num', '0x69'])).toBe(105n);
    expect(stackBigInt({ '@type': 'tvm.stackEntryNumber', number: { number: '106' } })).toBe(106n);
  });

  it('rejects unsafe JavaScript-number conversion', () => {
    expect(() => stackNumber(['num', '9007199254740992'])).toThrow(/safe range/);
  });

  it('decodes an addr_std returned as a TVM slice', () => {
    const address = parseRawAddress(`0:${'ab'.repeat(32)}`);
    const cell = new Builder();
    storeAddress(cell, address);
    const entry = ['slice', { bytes: bytesToBase64(serializeBoc(cell.endCell())) }];
    expect(stackAddress(entry)).toBe(`0:${'ab'.repeat(32)}`);
  });

  it('recognizes addr_none without inventing an owner', () => {
    const none = new Builder().storeUint(0, 2).endCell();
    expect(stackAddress(['slice', { bytes: bytesToBase64(serializeBoc(none)) }])).toBeNull();
  });

  it('rejects a same-height checkpoint with different hashes', () => {
    const checkpoint = { workchain: -1, seqno: 42, root_hash: 'root-a', file_hash: 'file-a' };
    expect(sameCheckpoint({ ...checkpoint }, checkpoint)).toBe(true);
    expect(sameCheckpoint({ ...checkpoint, root_hash: 'root-b' }, checkpoint)).toBe(false);
    expect(sameCheckpoint({ ...checkpoint, file_hash: 'file-b' }, checkpoint)).toBe(false);
  });
});
