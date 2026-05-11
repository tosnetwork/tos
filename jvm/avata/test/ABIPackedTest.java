// Pin ABI.encodePacked / encode / encodeWithSelector byte-level output.
public class ABIPackedTest {
  public static void main(String[] args) {
    packedConcatenation();
    packedDistinctTypes();
    encodeSliceShape();
    encodeWithSelectorShape();
    System.out.println("ABIPackedTest: encodePacked + encode + encodeWithSelector ok");
  }

  private static void packedConcatenation() {
    // encodePacked is tight, no padding — concatenation must match the
    // per-type direct concat.
    Bytes32 a = Bytes32.fromBytes(repeat((byte) 0x11));
    Bytes32 b = Bytes32.fromBytes(repeat((byte) 0x22));
    byte[] packed = ABI.encodePacked(new Object[] { a, b });
    if (packed.length != 64) {
      throw new RuntimeException(
          "encodePacked Bytes32+Bytes32 length expected 64, got " + packed.length);
    }
    for (int i = 0; i < 32; ++i) {
      if (packed[i] != 0x11) {
        throw new RuntimeException(
            "encodePacked Bytes32 left half corrupted at " + i);
      }
      if (packed[32 + i] != 0x22) {
        throw new RuntimeException(
            "encodePacked Bytes32 right half corrupted at " + i);
      }
    }
  }

  private static void packedDistinctTypes() {
    // String + Long packed — String contributes UTF-8 bytes without length,
    // Long contributes 8 big-endian bytes.
    byte[] out = ABI.encodePacked(
        new Object[] { "ABI", Long.valueOf(0x0102030405060708L) });
    if (out.length != 11) {
      throw new RuntimeException(
          "encodePacked String+Long length expected 11, got " + out.length);
    }
    if (out[0] != 'A' || out[1] != 'B' || out[2] != 'I') {
      throw new RuntimeException("encodePacked String prefix wrong");
    }
    byte[] expectedLong = new byte[] {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };
    for (int i = 0; i < 8; ++i) {
      if (out[3 + i] != expectedLong[i]) {
        throw new RuntimeException(
            "encodePacked Long byte " + i + " wrong");
      }
    }
  }

  private static void encodeSliceShape() {
    // Standard ABI.encode pads each scalar to 32 bytes.  Two Uint256 args
    // -> 64-byte output.
    byte[] out = ABI.encode(new Object[] {
        Uint256.valueOf(0x42L), Uint256.valueOf(0x99L)
    });
    if (out.length != 64) {
      throw new RuntimeException(
          "encode 2x Uint256 length expected 64, got " + out.length);
    }
    if (out[31] != 0x42 || out[63] != (byte) 0x99) {
      throw new RuntimeException("encode 2x Uint256 trailing byte wrong");
    }
  }

  private static void encodeWithSelectorShape() {
    Bytes4 sig = ABI.selector("transfer(address,uint256)");
    Address to = Address.fromHex(0,
        "1122334455667788990011223344556677889900112233445566778899001122");
    byte[] call = ABI.encodeWithSelector(sig,
        new Object[] { to, Uint256.valueOf(1000L) });
    // 4-byte selector + Address (36 bytes raw in our scheme) + Uint256 (32)
    // = 72 bytes.
    if (call.length != 4 + 36 + 32) {
      throw new RuntimeException(
          "encodeWithSelector length expected 72, got " + call.length);
    }
    byte[] sigBytes = sig.toByteArray();
    for (int i = 0; i < 4; ++i) {
      if (call[i] != sigBytes[i]) {
        throw new RuntimeException(
            "encodeWithSelector selector prefix wrong at " + i);
      }
    }
  }

  private static byte[] repeat(byte b) {
    byte[] out = new byte[32];
    for (int i = 0; i < 32; ++i) {
      out[i] = b;
    }
    return out;
  }
}
