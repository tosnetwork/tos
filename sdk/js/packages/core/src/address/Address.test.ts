import { describe, it, expect } from 'vitest';
import { Address, address } from './Address';
import {
    packAddress,
    unpackAddress,
    detectAddress,
} from './utils';
import { bytesToHex } from '../utils/encoding';

const RAW =
    '0:2cf55953e92efbeadab7ba725c3f93a0b23f842cbba72d7b8e6f510a70e422e3';
const HASH_HEX =
    '2cf55953e92efbeadab7ba725c3f93a0b23f842cbba72d7b8e6f510a70e422e3';

// Friendly addresses from ton-core reference tests
const FRIENDLY_NON_BOUNCEABLE_TEST =
    '0QAs9VlT6S776tq3unJcP5Ogsj-ELLunLXuOb1EKcOQi4-QO';
const FRIENDLY_BOUNCEABLE_TEST =
    'kQAs9VlT6S776tq3unJcP5Ogsj-ELLunLXuOb1EKcOQi47nL';
const FRIENDLY_BOUNCEABLE =
    'EQAs9VlT6S776tq3unJcP5Ogsj-ELLunLXuOb1EKcOQi4wJB';

describe('Address', () => {
    // ---- Parse raw address ----
    it('should parse raw address string and verify workchain / hash', () => {
        const addr = Address.parseRaw(RAW);
        expect(addr.workchain).toBe(0);
        expect(bytesToHex(addr.hash)).toBe(HASH_HEX);
    });

    // ---- Parse friendly address ----
    it('should parse friendly (base64) address to the same raw address', () => {
        const parsed = Address.parseFriendly(FRIENDLY_NON_BOUNCEABLE_TEST);
        expect(parsed.isBounceable).toBe(false);
        expect(parsed.isTestOnly).toBe(true);
        expect(parsed.address.workchain).toBe(0);
        expect(bytesToHex(parsed.address.hash)).toBe(HASH_HEX);
    });

    it('should parse bounceable friendly address', () => {
        const parsed = Address.parseFriendly(FRIENDLY_BOUNCEABLE_TEST);
        expect(parsed.isBounceable).toBe(true);
        expect(parsed.isTestOnly).toBe(true);
        expect(parsed.address.workchain).toBe(0);
        expect(bytesToHex(parsed.address.hash)).toBe(HASH_HEX);
    });

    // ---- Round-trip ----
    it('should round-trip: parse -> toString -> parse -> equals', () => {
        const a = Address.parseRaw(RAW);
        const friendly = a.toString();
        const b = Address.parse(friendly);
        expect(a.equals(b)).toBe(true);
    });

    it('should round-trip via friendly format', () => {
        const a = Address.parse(FRIENDLY_BOUNCEABLE);
        const raw = a.toRawString();
        const b = Address.parseRaw(raw);
        expect(a.equals(b)).toBe(true);
    });

    // ---- isValid ----
    it('should return true for valid addresses', () => {
        expect(Address.isValid(RAW)).toBe(true);
        expect(Address.isValid(FRIENDLY_BOUNCEABLE)).toBe(true);
        expect(Address.isValid(FRIENDLY_NON_BOUNCEABLE_TEST)).toBe(true);
    });

    it('should return false for garbage input', () => {
        expect(Address.isValid('not-an-address')).toBe(false);
        expect(Address.isValid('')).toBe(false);
        expect(Address.isValid('0:gg')).toBe(false);
    });

    // ---- parseRaw rejects friendly, parseFriendly rejects raw ----
    it('parseRaw should reject friendly format', () => {
        expect(() => Address.parseRaw(FRIENDLY_BOUNCEABLE)).toThrow();
    });

    it('parseFriendly should reject raw format', () => {
        expect(() => Address.parseFriendly(RAW)).toThrow();
    });

    // ---- equals ----
    it('should equal same address', () => {
        const a = Address.parseRaw(RAW);
        const b = Address.parseRaw(RAW);
        expect(a.equals(b)).toBe(true);
    });

    it('should not equal different workchain', () => {
        const a = Address.parseRaw(RAW);
        const b = Address.parseRaw(
            '-1:2cf55953e92efbeadab7ba725c3f93a0b23f842cbba72d7b8e6f510a70e422e3',
        );
        expect(a.equals(b)).toBe(false);
    });

    it('should not equal different hash', () => {
        const a = Address.parseRaw(RAW);
        const b = Address.parseRaw(
            '0:2cf55953e92efbeadab7ba725c3f93a0b23f842cbba72d7b8e6f510a70e422e5',
        );
        expect(a.equals(b)).toBe(false);
    });

    // ---- address() shortcut ----
    it('address() shortcut should parse correctly', () => {
        const a = address(RAW);
        expect(a.workchain).toBe(0);
        expect(bytesToHex(a.hash)).toBe(HASH_HEX);
    });

    // ---- toString variants ----
    it('should serialize to expected friendly forms', () => {
        const addr = Address.parseRaw(RAW);

        expect(addr.toString()).toBe(FRIENDLY_BOUNCEABLE);
        expect(addr.toString({ bounceable: false, testOnly: true })).toBe(
            FRIENDLY_NON_BOUNCEABLE_TEST,
        );
        expect(addr.toString({ testOnly: true })).toBe(
            FRIENDLY_BOUNCEABLE_TEST,
        );
    });

    // ---- Workchain -1 ----
    it('should handle workchain -1', () => {
        const addr = Address.parse(
            '-1:3333333333333333333333333333333333333333333333333333333333333333',
        );
        expect(addr.workchain).toBe(-1);
        expect(bytesToHex(addr.hash)).toBe(
            '3333333333333333333333333333333333333333333333333333333333333333',
        );
    });

    // ---- Invalid address errors ----
    it('should throw on invalid raw address (short hash)', () => {
        expect(() =>
            Address.parseRaw(
                '0:2cf55953e92efbeadab7ba725c3f93a0b23f842cbba72d7b8e6f510a70e422',
            ),
        ).toThrow();
    });

    // ---- isRaw / isFriendly ----
    it('isRaw detects raw format', () => {
        expect(Address.isRaw(RAW)).toBe(true);
        expect(Address.isRaw(FRIENDLY_BOUNCEABLE)).toBe(false);
    });

    it('isFriendly detects friendly format', () => {
        expect(Address.isFriendly(FRIENDLY_BOUNCEABLE)).toBe(true);
        expect(Address.isFriendly(RAW)).toBe(false);
    });
});

describe('Address utilities', () => {
    it('packAddress converts raw to friendly', () => {
        const friendly = packAddress(RAW);
        const back = unpackAddress(friendly);
        expect(back).toBe(RAW);
    });

    it('unpackAddress converts friendly to raw', () => {
        const raw = unpackAddress(FRIENDLY_BOUNCEABLE);
        expect(raw).toBe(RAW);
    });

    it('detectAddress returns full info for a raw address', () => {
        const info = detectAddress(RAW);
        expect(info.is_valid).toBe(true);
        expect(info.raw_form).toBe(RAW);
        expect(info.workchain).toBe(0);
        expect(info.hash_hex).toBe(HASH_HEX);
        expect(info.bounceable_b64url.length).toBe(48);
        expect(info.non_bounceable_b64url.length).toBe(48);
    });

    it('detectAddress returns is_valid=false for garbage', () => {
        const info = detectAddress('garbage');
        expect(info.is_valid).toBe(false);
    });
});
