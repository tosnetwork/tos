package java.lang;

// Pure Java crypto helpers are covered by opcode, allocation, and arraycopy
// gas. If any helper is moved to a native implementation, that native entry
// must charge explicit helper gas proportional to its input size.
public final class Crypto {
  private static final int KECCAK_256_RATE = 136;

  private static final long[] KECCAK_ROUND_CONSTANTS = new long[] {
    0x0000000000000001L, 0x0000000000008082L,
    0x800000000000808aL, 0x8000000080008000L,
    0x000000000000808bL, 0x0000000080000001L,
    0x8000000080008081L, 0x8000000000008009L,
    0x000000000000008aL, 0x0000000000000088L,
    0x0000000080008009L, 0x000000008000000aL,
    0x000000008000808bL, 0x800000000000008bL,
    0x8000000000008089L, 0x8000000000008003L,
    0x8000000000008002L, 0x8000000000000080L,
    0x000000000000800aL, 0x800000008000000aL,
    0x8000000080008081L, 0x8000000000008080L,
    0x0000000080000001L, 0x8000000080008008L
  };

  private static final int[] KECCAK_ROTATION = new int[] {
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14
  };

  private Crypto() { }

  public static Bytes32 keccak256(byte[] input) {
    return Bytes32.wrap(keccak256Bytes(input));
  }

  public static Bytes32 keccak256(byte[] first, byte[] second) {
    return keccak256(ABI.concat(first, second));
  }

  public static Bytes32 keccak256(Bytes32 left, Bytes32 right) {
    return keccak256(left.rawBytes(), right.rawBytes());
  }

  public static byte[] keccak256Bytes(byte[] input) {
    long[] state = new long[25];
    int offset = 0;
    while (input.length - offset >= KECCAK_256_RATE) {
      absorbBlock(state, input, offset);
      keccakF1600(state);
      offset += KECCAK_256_RATE;
    }

    byte[] block = new byte[KECCAK_256_RATE];
    int remaining = input.length - offset;
    for (int i = 0; i < remaining; ++i) {
      block[i] = input[offset + i];
    }
    block[remaining] ^= 0x01;
    block[KECCAK_256_RATE - 1] ^= (byte) 0x80;
    absorbBlock(state, block, 0);
    keccakF1600(state);

    byte[] out = new byte[Bytes32.LENGTH];
    for (int i = 0; i < out.length; ++i) {
      out[i] = (byte) (state[i >>> 3] >>> ((i & 7) * 8));
    }
    return out;
  }

  private static void absorbBlock(long[] state, byte[] block, int offset) {
    for (int i = 0; i < KECCAK_256_RATE / 8; ++i) {
      state[i] ^= loadLittleEndian64(block, offset + i * 8);
    }
  }

  private static long loadLittleEndian64(byte[] bytes, int offset) {
    return ((long) bytes[offset] & 0xff)
        | (((long) bytes[offset + 1] & 0xff) << 8)
        | (((long) bytes[offset + 2] & 0xff) << 16)
        | (((long) bytes[offset + 3] & 0xff) << 24)
        | (((long) bytes[offset + 4] & 0xff) << 32)
        | (((long) bytes[offset + 5] & 0xff) << 40)
        | (((long) bytes[offset + 6] & 0xff) << 48)
        | (((long) bytes[offset + 7] & 0xff) << 56);
  }

  private static void keccakF1600(long[] a) {
    long[] b = new long[25];
    long[] c = new long[5];
    long[] d = new long[5];

    for (int round = 0; round < KECCAK_ROUND_CONSTANTS.length; ++round) {
      for (int x = 0; x < 5; ++x) {
        c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
      }

      for (int x = 0; x < 5; ++x) {
        d[x] = c[(x + 4) % 5] ^ rotateLeft(c[(x + 1) % 5], 1);
      }

      for (int y = 0; y < 5; ++y) {
        for (int x = 0; x < 5; ++x) {
          a[x + 5 * y] ^= d[x];
        }
      }

      for (int y = 0; y < 5; ++y) {
        for (int x = 0; x < 5; ++x) {
          int source = x + 5 * y;
          int target = y + 5 * ((2 * x + 3 * y) % 5);
          b[target] = rotateLeft(a[source], KECCAK_ROTATION[source]);
        }
      }

      for (int y = 0; y < 5; ++y) {
        for (int x = 0; x < 5; ++x) {
          a[x + 5 * y] = b[x + 5 * y]
              ^ ((~b[((x + 1) % 5) + 5 * y])
                 & b[((x + 2) % 5) + 5 * y]);
        }
      }

      a[0] ^= KECCAK_ROUND_CONSTANTS[round];
    }
  }

  private static long rotateLeft(long value, int distance) {
    return (value << distance) | (value >>> (64 - distance));
  }
}
