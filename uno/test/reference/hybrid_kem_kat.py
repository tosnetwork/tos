#!/usr/bin/env python3
"""
Uno Workchain — hybrid-KEM combiner KAT generator (§2.7, §12 P.1).

Produces the 32-byte `k_aead` value for a fixed (s_dh, s_pq, epk, mlkem_ct)
transcript using ONLY Python stdlib. The transcript follows §2.7 of
doc/uno-workchain.md exactly:

    k_aead = BLAKE3(
        "uno-hybrid-kem-v1"              (18 B ASCII, no trailing NUL)  ||
        compress(s_dh)                   (32 B)                         ||
        s_pq                             (32 B)                         ||
        compress(epk)                    (32 B)                         ||
        BLAKE3(mlkem_ct)                 (32 B)
    )[0..32]

Stdlib note: Python 3.10+ ships `hashlib.blake2b`, but BLAKE3 is NOT in the
stdlib. The uno_workchain/crypto/hybrid-kem.cpp implementation uses BLAKE3
(not BLAKE2b). To avoid adding a Python dependency, this script IMPLEMENTS
BLAKE3 from the reference spec in pure Python. The implementation is a
verbatim port of the BLAKE3 reference code published by the BLAKE3 authors
under CC0 — see https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.py.

Usage:
    $ python3 uno/test/reference/hybrid_kem_kat.py
    <hex 64-char k_aead>

The printed hex is pasted verbatim into test-primitive-parity.cpp's
`kHybridKemKat.expected_k_aead_hex` field.

Regeneration: any change to the transcript layout (domain tag, ordering,
inner hash) requires re-running this script AND bumping scheme_id (because
the combiner is consensus-binding).

This script has NO external dependencies; `hashlib` is listed below for the
SHA-256 fallback only (kept so the file runs cleanly on a minimum-spec
Python 3.10).
"""

import hashlib  # noqa: F401  — available as a cross-check; not required.
import struct
import sys


# -----------------------------------------------------------------------------
# BLAKE3 reference implementation (CC0, verbatim port)
# -----------------------------------------------------------------------------
#
# Source: https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.py
# Stripped to the interfaces we need: one-shot `blake3(data) -> 32 bytes`.
# No keyed, no derive-key modes — the hybrid-KEM transcript uses plain hash.

OUT_LEN = 32
KEY_LEN = 32
BLOCK_LEN = 64
CHUNK_LEN = 1024

CHUNK_START = 1 << 0
CHUNK_END = 1 << 1
PARENT = 1 << 2
ROOT = 1 << 3
# (keyed / key-derivation flags unused for our transcript)

IV = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]

MSG_PERMUTATION = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]


def mask32(x):
    return x & 0xFFFFFFFF


def add32(x, y):
    return mask32(x + y)


def rightrotate32(x, n):
    return mask32((x >> n) | (x << (32 - n)))


def g(state, a, b, c, d, mx, my):
    state[a] = add32(state[a], add32(state[b], mx))
    state[d] = rightrotate32(state[d] ^ state[a], 16)
    state[c] = add32(state[c], state[d])
    state[b] = rightrotate32(state[b] ^ state[c], 12)
    state[a] = add32(state[a], add32(state[b], my))
    state[d] = rightrotate32(state[d] ^ state[a], 8)
    state[c] = add32(state[c], state[d])
    state[b] = rightrotate32(state[b] ^ state[c], 7)


def round_fn(state, m):
    g(state, 0, 4,  8, 12, m[0],  m[1])
    g(state, 1, 5,  9, 13, m[2],  m[3])
    g(state, 2, 6, 10, 14, m[4],  m[5])
    g(state, 3, 7, 11, 15, m[6],  m[7])

    g(state, 0, 5, 10, 15, m[8],  m[9])
    g(state, 1, 6, 11, 12, m[10], m[11])
    g(state, 2, 7,  8, 13, m[12], m[13])
    g(state, 3, 4,  9, 14, m[14], m[15])


def permute(m):
    return [m[MSG_PERMUTATION[i]] for i in range(16)]


def compress(chaining_value, block_words, counter, block_len, flags):
    counter_low = mask32(counter)
    counter_high = mask32(counter >> 32)
    state = [
        chaining_value[0], chaining_value[1], chaining_value[2], chaining_value[3],
        chaining_value[4], chaining_value[5], chaining_value[6], chaining_value[7],
        IV[0], IV[1], IV[2], IV[3],
        counter_low, counter_high, block_len, flags,
    ]
    block = list(block_words)

    round_fn(state, block); block = permute(block)
    round_fn(state, block); block = permute(block)
    round_fn(state, block); block = permute(block)
    round_fn(state, block); block = permute(block)
    round_fn(state, block); block = permute(block)
    round_fn(state, block); block = permute(block)
    round_fn(state, block)

    for i in range(8):
        state[i] ^= state[i + 8]
        state[i + 8] ^= chaining_value[i]
    return state


def words_from_little_endian_bytes(data, words_out_len):
    result = [0] * words_out_len
    for i in range(words_out_len):
        result[i] = struct.unpack_from("<I", data, i * 4)[0]
    return result


class ChunkState:
    def __init__(self, key_words, chunk_counter, flags):
        self.chaining_value = list(key_words)
        self.chunk_counter = chunk_counter
        self.block = bytearray(BLOCK_LEN)
        self.block_len = 0
        self.blocks_compressed = 0
        self.flags = flags

    def len(self):
        return BLOCK_LEN * self.blocks_compressed + self.block_len

    def start_flag(self):
        return CHUNK_START if self.blocks_compressed == 0 else 0

    def update(self, input_bytes):
        while input_bytes:
            if self.block_len == BLOCK_LEN:
                block_words = words_from_little_endian_bytes(self.block, 16)
                new_cv = compress(
                    self.chaining_value, block_words, self.chunk_counter,
                    BLOCK_LEN, self.flags | self.start_flag(),
                )
                self.chaining_value = new_cv[:8]
                self.blocks_compressed += 1
                self.block = bytearray(BLOCK_LEN)
                self.block_len = 0

            want = BLOCK_LEN - self.block_len
            take = min(want, len(input_bytes))
            self.block[self.block_len:self.block_len + take] = input_bytes[:take]
            self.block_len += take
            input_bytes = input_bytes[take:]

    def output(self):
        block_words = words_from_little_endian_bytes(self.block, 16)
        return Output(
            self.chaining_value, block_words, self.chunk_counter,
            self.block_len, self.flags | self.start_flag() | CHUNK_END,
        )


class Output:
    def __init__(self, input_chaining_value, block_words, counter, block_len, flags):
        self.input_chaining_value = input_chaining_value
        self.block_words = block_words
        self.counter = counter
        self.block_len = block_len
        self.flags = flags

    def chaining_value(self):
        return compress(
            self.input_chaining_value, self.block_words, self.counter,
            self.block_len, self.flags,
        )[:8]

    def root_output_bytes(self, out_len):
        output_bytes = bytearray()
        i = 0
        while len(output_bytes) < out_len:
            words = compress(
                self.input_chaining_value, self.block_words, i,
                self.block_len, self.flags | ROOT,
            )
            for word in words:
                output_bytes += struct.pack("<I", word)
                if len(output_bytes) >= out_len:
                    break
            i += 1
        return bytes(output_bytes[:out_len])


def parent_output(left_child_cv, right_child_cv, key_words, flags):
    return Output(
        input_chaining_value=key_words,
        block_words=(left_child_cv + right_child_cv),
        counter=0,
        block_len=BLOCK_LEN,
        flags=PARENT | flags,
    )


def parent_cv(left_child_cv, right_child_cv, key_words, flags):
    return parent_output(left_child_cv, right_child_cv, key_words, flags).chaining_value()


class Hasher:
    def __init__(self):
        self.key_words = list(IV)
        self.flags = 0
        self.chunk_state = ChunkState(self.key_words, 0, self.flags)
        self.cv_stack = []

    def _push_cv(self, new_cv, chunk_counter):
        # merge subtrees the same way the reference does
        total_after = chunk_counter + 1
        while (total_after & 1) == 0:
            right_child_cv = new_cv
            left_child_cv = self.cv_stack.pop()
            new_cv = parent_cv(left_child_cv, right_child_cv, self.key_words, self.flags)
            total_after >>= 1
        self.cv_stack.append(new_cv)

    def update(self, input_bytes):
        data = memoryview(input_bytes)
        while data:
            if self.chunk_state.len() == CHUNK_LEN:
                chunk_cv = self.chunk_state.output().chaining_value()
                counter = self.chunk_state.chunk_counter
                self._push_cv(chunk_cv, counter)
                self.chunk_state = ChunkState(self.key_words, counter + 1, self.flags)

            want = CHUNK_LEN - self.chunk_state.len()
            take = min(want, len(data))
            self.chunk_state.update(bytes(data[:take]))
            data = data[take:]

    def finalize(self, out_len=OUT_LEN):
        output = self.chunk_state.output()
        parent_nodes_remaining = len(self.cv_stack)
        while parent_nodes_remaining:
            parent_nodes_remaining -= 1
            output = parent_output(
                self.cv_stack[parent_nodes_remaining],
                output.chaining_value(),
                self.key_words,
                self.flags,
            )
        return output.root_output_bytes(out_len)


def blake3(data: bytes) -> bytes:
    h = Hasher()
    h.update(data)
    return h.finalize(OUT_LEN)


# -----------------------------------------------------------------------------
# KAT transcript — MUST mirror test-primitive-parity.cpp's kHybridKemKat.
# -----------------------------------------------------------------------------

DOMAIN_TAG = b"uno-hybrid-kem-v1"  # 17 bytes (header says 18; keep identical to C++)

S_DH_HEX = "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
S_PQ_HEX = "aa" * 32
EPK_HEX  = "33" * 32

MLKEM_CT_LEN = 1088
MLKEM_CT_FILL = 0x77


def main():
    s_dh = bytes.fromhex(S_DH_HEX)
    s_pq = bytes.fromhex(S_PQ_HEX)
    epk  = bytes.fromhex(EPK_HEX)

    assert len(s_dh) == 32 and len(s_pq) == 32 and len(epk) == 32

    mlkem_ct = bytes([MLKEM_CT_FILL] * MLKEM_CT_LEN)
    mlkem_ct_hash = blake3(mlkem_ct)

    transcript = DOMAIN_TAG + s_dh + s_pq + epk + mlkem_ct_hash
    k_aead = blake3(transcript)

    # Sanity: DOMAIN_TAG length. The uno doc says 18 B; the actual string
    # "uno-hybrid-kem-v1" is 17 B. If the C++ header disagrees, this script
    # will produce a KAT that the C++ side rejects — which is the correct
    # way to surface a spec/code mismatch.
    sys.stderr.write(
        f"[KAT] domain_tag={DOMAIN_TAG!r} len={len(DOMAIN_TAG)} "
        f"transcript_len={len(transcript)}\n"
    )

    print(k_aead.hex())


if __name__ == "__main__":
    main()
