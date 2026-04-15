/**
 * BOC serialization reference vectors.
 * These vectors come from the ton-core C++ reference-compatible test suite.
 */

import { describe, it, expect } from 'vitest';
import { Cell } from './Cell';
import { beginCell } from './Builder';
import { hexToBytes, bytesToHex } from '../utils/encoding';

// Wallet contract BOC hex strings from ton-core reference tests
const walletBocs: string[] = [
    'B5EE9C72410101010044000084FF0020DDA4F260810200D71820D70B1FED44D0D31FD3FFD15112BAF2A122F901541044F910F2A2F80001D31F3120D74A96D307D402FB00DED1A4C8CB1FCBFFC9ED5441FDF089',
    'B5EE9C724101010100530000A2FF0020DD2082014C97BA9730ED44D0D70B1FE0A4F260810200D71820D70B1FED44D0D31FD3FFD15112BAF2A122F901541044F910F2A2F80001D31F3120D74A96D307D402FB00DED1A4C8CB1FCBFFC9ED54D0E2786F',
    'B5EE9C7241010101005F0000BAFF0020DD2082014C97BA218201339CBAB19C71B0ED44D0D31FD70BFFE304E0A4F260810200D71820D70B1FED44D0D31FD3FFD15112BAF2A122F901541044F910F2A2F80001D31F3120D74A96D307D402FB00DED1A4C8CB1FCBFFC9ED54B5B86E42',
    'B5EE9C724101010100570000AAFF0020DD2082014C97BA9730ED44D0D70B1FE0A4F2608308D71820D31FD31F01F823BBF263ED44D0D31FD3FFD15131BAF2A103F901541042F910F2A2F800029320D74A96D307D402FB00E8D1A4C8CB1FCBFFC9ED54A1370BB6',
    'B5EE9C724101010100630000C2FF0020DD2082014C97BA218201339CBAB19C71B0ED44D0D31FD70BFFE304E0A4F2608308D71820D31FD31F01F823BBF263ED44D0D31FD3FFD15131BAF2A103F901541042F910F2A2F800029320D74A96D307D402FB00E8D1A4C8CB1FCBFFC9ED54044CD7A1',
    'B5EE9C724101010100620000C0FF0020DD2082014C97BA9730ED44D0D70B1FE0A4F2608308D71820D31FD31FD31FF82313BBF263ED44D0D31FD31FD3FFD15132BAF2A15144BAF2A204F901541055F910F2A3F8009320D74A96D307D402FB00E8D101A4C8CB1FCB1FCBFFC9ED543FBE6EE0',
    'B5EE9C724101010100710000DEFF0020DD2082014C97BA218201339CBAB19F71B0ED44D0D31FD31F31D70BFFE304E0A4F2608308D71820D31FD31FD31FF82313BBF263ED44D0D31FD31FD3FFD15132BAF2A15144BAF2A204F901541055F910F2A3F8009320D74A96D307D402FB00E8D101A4C8CB1FCB1FCBFFC9ED5410BD6DAD',
];

describe('BOC reference vectors', () => {
    // ---- Wallet contract round-trips ----
    describe('wallet contract BOCs', () => {
        for (let i = 0; i < walletBocs.length; i++) {
            it(`wallet BOC #${i} should deserialize and re-serialize to identical cell hash`, () => {
                const hex = walletBocs[i]!;
                const bytes = hexToBytes(hex.toLowerCase());
                const cells = Cell.fromBoc(bytes);
                expect(cells.length).toBe(1);
                const cell = cells[0]!;

                // Re-serialize with crc32
                const reserialized = cell.toBoc({ idx: false, crc32: true });
                const cells2 = Cell.fromBoc(reserialized);
                expect(cells2[0]!.equals(cell)).toBe(true);
            });
        }
    });

    // ---- Empty cell ----
    describe('empty cell serialization', () => {
        it('should serialize empty cell and match known base64', () => {
            const cell = beginCell().endCell();
            expect(cell.bits.length).toBe(0);
            expect(cell.refs.length).toBe(0);

            // Known base64 for empty cell (no idx, no crc32)
            const b64NoCrc = 'te6ccgEBAQEAAgAAAA==';
            const parsed = Cell.fromBase64(b64NoCrc);
            expect(parsed.equals(cell)).toBe(true);
        });

        it('should deserialize empty cell from known base64 with crc32', () => {
            const b64Crc = 'te6cckEBAQEAAgAAAEysuc0=';
            const cell = Cell.fromBase64(b64Crc);
            expect(cell.bits.length).toBe(0);
            expect(cell.refs.length).toBe(0);
        });
    });

    // ---- Single cell with byte-aligned bits ----
    describe('cell with uint(123456789, 32)', () => {
        const knownVectors = {
            noIdxNoCrc: 'te6ccgEBAQEABgAACAdbzRU=',
            noIdxCrc: 'te6cckEBAQEABgAACAdbzRVRblCS',
        };

        it('should deserialize from known base64 (no idx, no crc)', () => {
            const cell = Cell.fromBase64(knownVectors.noIdxNoCrc);
            expect(cell.beginParse().loadUint(32)).toBe(123456789);
        });

        it('should deserialize from known base64 (no idx, crc)', () => {
            const cell = Cell.fromBase64(knownVectors.noIdxCrc);
            expect(cell.beginParse().loadUint(32)).toBe(123456789);
        });

        it('should round-trip through toBoc/fromBoc', () => {
            const cell = beginCell().storeUint(123456789, 32).endCell();
            const boc = cell.toBoc({ idx: false, crc32: true });
            const restored = Cell.fromBoc(boc)[0]!;
            expect(restored.equals(cell)).toBe(true);
        });

        it('cell toString should match known repr', () => {
            const cell = beginCell().storeUint(123456789, 32).endCell();
            expect(cell.toString()).toBe('x{075BCD15}');
        });
    });

    // ---- Non-aligned bits ----
    describe('cell with uint(123456789, 34) -- non-aligned', () => {
        it('should deserialize from known base64', () => {
            const cell = Cell.fromBase64('te6ccgEBAQEABwAACQHW80Vg');
            expect(cell.toString()).toBe('x{01D6F3456_}');
        });

        it('should round-trip', () => {
            const cell = beginCell().storeUint(123456789, 34).endCell();
            const boc = cell.toBoc();
            const restored = Cell.fromBoc(boc)[0]!;
            expect(restored.equals(cell)).toBe(true);
        });
    });

    // ---- Single cell with one reference ----
    describe('cell with one reference', () => {
        it('should deserialize from known base64', () => {
            const cell = Cell.fromBase64('te6ccgEBAgEADQABCDreaLEBAAgHW80V');
            const s = cell.beginParse();
            expect(s.loadUint(32)).toBe(987654321);
            const ref = s.loadRef();
            expect(ref.beginParse().loadUint(32)).toBe(123456789);
        });

        it('toString should match known repr', () => {
            const refCell = beginCell().storeUint(123456789, 32).endCell();
            const cell = beginCell()
                .storeUint(987654321, 32)
                .storeRef(refCell)
                .endCell();
            expect(cell.toString()).toBe('x{3ADE68B1}\n x{075BCD15}');
        });

        it('should round-trip', () => {
            const refCell = beginCell().storeUint(123456789, 32).endCell();
            const cell = beginCell()
                .storeUint(987654321, 32)
                .storeRef(refCell)
                .endCell();
            const boc = cell.toBoc();
            const restored = Cell.fromBoc(boc)[0]!;
            expect(restored.equals(cell)).toBe(true);
        });
    });

    // ---- Multiple references ----
    describe('cell with multiple references', () => {
        it('should deserialize from known base64', () => {
            const cell = Cell.fromBase64('te6ccgEBAgEADwADCDreaLEBAQEACAdbzRU=');
            expect(cell.refs.length).toBe(3);
            expect(cell.beginParse().loadUint(32)).toBe(987654321);
            for (const ref of cell.refs) {
                expect(ref.beginParse().loadUint(32)).toBe(123456789);
            }
        });

        it('toString should match known repr', () => {
            const refCell = beginCell().storeUint(123456789, 32).endCell();
            const cell = beginCell()
                .storeUint(987654321, 32)
                .storeRef(refCell)
                .storeRef(refCell)
                .storeRef(refCell)
                .endCell();
            expect(cell.toString()).toBe(
                'x{3ADE68B1}\n x{075BCD15}\n x{075BCD15}\n x{075BCD15}',
            );
        });
    });

    // ---- Cell.fromHex ----
    describe('Cell.fromHex', () => {
        it('should deserialize from known hex', () => {
            const cell = Cell.fromHex(
                'b5ee9c7241010201000d00010800000001010008000000027d4b3cf8',
            );
            expect(cell.toString()).toBe('x{00000001}\n x{00000002}');
        });
    });

    // ---- BOC with index ----
    describe('BOC with index', () => {
        it('should produce known hex when serialized with idx=true', () => {
            const cell = beginCell()
                .storeUint(228, 32)
                .storeRef(beginCell().storeUint(1337, 32).endCell())
                .storeRef(beginCell().storeUint(1338, 32).endCell())
                .endCell();

            expect(cell.toString()).toBe(
                'x{000000E4}\n x{00000539}\n x{0000053A}',
            );

            const serialized = bytesToHex(cell.toBoc({ idx: true, crc32: false }));
            expect(serialized).toBe(
                'b5ee9c7281010301001400080e140208000000e4010200080000053900080000053a',
            );
        });
    });

    // ---- Cross-format: base64 -> hex -> base64 ----
    describe('cross-format round-trip', () => {
        it('base64 -> Cell -> hex -> Cell -> equals', () => {
            const b64 = 'te6cckEBAQEABgAACAdbzRVRblCS';
            const cell1 = Cell.fromBase64(b64);
            const hex = cell1.toHex();
            const cell2 = Cell.fromHex(hex);
            expect(cell2.equals(cell1)).toBe(true);
        });
    });

    // ---- Large value round-trip ----
    describe('large integer round-trip', () => {
        it('should handle 256-bit uint', () => {
            const bigVal =
                0xdeadbeefcafebabe1234567890abcdef_deadbeefcafebabe1234567890abcdefn;
            const cell = beginCell().storeUint(bigVal, 256).endCell();
            const boc = cell.toBoc();
            const restored = Cell.fromBoc(boc)[0]!;
            expect(restored.beginParse().loadUintBig(256)).toBe(bigVal);
        });
    });

    // ---- Deep nesting ----
    describe('deep nesting', () => {
        it('should handle deeply nested cells (chain of refs)', () => {
            // Build a chain: cell -> ref -> ref -> ref
            let current = beginCell().storeUint(0, 8).endCell();
            for (let i = 1; i <= 5; i++) {
                current = beginCell()
                    .storeUint(i, 8)
                    .storeRef(current)
                    .endCell();
            }

            const boc = current.toBoc();
            let restored = Cell.fromBoc(boc)[0]!;

            // Walk the chain
            for (let i = 5; i >= 1; i--) {
                const s = restored.beginParse();
                expect(s.loadUint(8)).toBe(i);
                restored = s.loadRef();
            }
            expect(restored.beginParse().loadUint(8)).toBe(0);
        });
    });

    // ---- Shared references (DAG) ----
    describe('shared references (DAG)', () => {
        it('should correctly serialize/deserialize cells with shared refs', () => {
            const shared = beginCell().storeUint(42, 32).endCell();
            const parent = beginCell()
                .storeUint(1, 8)
                .storeRef(shared)
                .storeRef(shared)
                .endCell();

            const boc = parent.toBoc();
            const restored = Cell.fromBoc(boc)[0]!;
            expect(restored.equals(parent)).toBe(true);
            // Both refs should have the same hash
            const r1 = restored.refs[0]!;
            const r2 = restored.refs[1]!;
            expect(r1.equals(r2)).toBe(true);
            expect(r1.beginParse().loadUint(32)).toBe(42);
        });
    });

    // ---- toBoc options ----
    describe('toBoc options', () => {
        it('default options produce valid BOC', () => {
            const cell = beginCell().storeUint(1, 8).endCell();
            const boc = cell.toBoc();
            expect(Cell.fromBoc(boc)[0]!.equals(cell)).toBe(true);
        });

        it('idx=false, crc32=false produce valid BOC', () => {
            const cell = beginCell().storeUint(1, 8).endCell();
            const boc = cell.toBoc({ idx: false, crc32: false });
            expect(Cell.fromBoc(boc)[0]!.equals(cell)).toBe(true);
        });

        it('idx=true, crc32=true produce valid BOC', () => {
            const cell = beginCell().storeUint(1, 8).endCell();
            const boc = cell.toBoc({ idx: true, crc32: true });
            expect(Cell.fromBoc(boc)[0]!.equals(cell)).toBe(true);
        });

        it('idx=true, crc32=false produce valid BOC', () => {
            const cell = beginCell().storeUint(1, 8).endCell();
            const boc = cell.toBoc({ idx: true, crc32: false });
            expect(Cell.fromBoc(boc)[0]!.equals(cell)).toBe(true);
        });
    });
});
