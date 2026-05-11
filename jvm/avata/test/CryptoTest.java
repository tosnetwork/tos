// Standalone-runner sanity check for java.lang.Crypto.
//
// The standalone Avata test harness installs no AvataCryptoHost, so every
// signature primitive must trap deterministically with
// ContractViolationError. keccak256 is a pure-Java implementation and
// stays available, so we sanity-check one known-answer vector to detect
// accidental regressions in the in-tree Keccak code.
//
// Real cross-platform conformance vectors for the sigverify primitives
// (Linux x86_64 ↔ macOS arm64 byte-identity) live in the C++ workchain
// integration tests under crypto/test/test-workchain-execution-registry.cpp,
// which have the production crypto host wired through jvm/core/crypto-host.cpp.
public class CryptoTest {
  public static void main(String[] args) {
    keccak256KnownAnswer();
    sigverifyTraps();
    System.out.println("CryptoTest: keccak256 KAT ok; sigverify primitives trap without host");
  }

  private static void keccak256KnownAnswer() {
    // keccak256("") = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    Bytes32 emptyHash = Crypto.keccak256(new byte[0]);
    String expected =
        "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
    String actual = bytesToHex(emptyHash.toByteArray());
    if (! expected.equals(actual)) {
      throw new RuntimeException(
          "keccak256(\"\") expected " + expected + " got " + actual);
    }

    // keccak256("abc") = 0x4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45
    Bytes32 abcHash = Crypto.keccak256("abc".getBytes());
    String expectedAbc =
        "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45";
    String actualAbc = bytesToHex(abcHash.toByteArray());
    if (! expectedAbc.equals(actualAbc)) {
      throw new RuntimeException(
          "keccak256(\"abc\") expected " + expectedAbc + " got " + actualAbc);
    }
  }

  private static void sigverifyTraps() {
    expectViolation("sha256", new Runnable() {
      public void run() { Crypto.sha256(new byte[0]); }
    });
    expectViolation("ecRecover", new Runnable() {
      public void run() {
        Crypto.ecRecover(Bytes32.ZERO, new byte[65]);
      }
    });
    expectViolation("ecdsaVerify", new Runnable() {
      public void run() {
        Crypto.ecdsaVerify(new byte[33], Bytes32.ZERO, new byte[64]);
      }
    });
    expectViolation("ed25519Verify", new Runnable() {
      public void run() {
        Crypto.ed25519Verify(new byte[32], new byte[0], new byte[64]);
      }
    });
    expectViolation("bls12381Verify", new Runnable() {
      public void run() {
        Crypto.bls12381Verify(new byte[48], new byte[0], new byte[96]);
      }
    });
  }

  private static void expectViolation(String name, Runnable r) {
    try {
      r.run();
    } catch (ContractViolationError e) {
      return;
    } catch (Throwable t) {
      throw new RuntimeException(
          "Crypto." + name + " threw wrong exception: " + t.getClass());
    }
    throw new RuntimeException(
        "Crypto." + name + " did not trap without an installed host");
  }

  private static String bytesToHex(byte[] bytes) {
    char[] hex = new char[bytes.length * 2];
    char[] alphabet = new char[] {
        '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'
    };
    for (int i = 0; i < bytes.length; ++i) {
      int v = bytes[i] & 0xff;
      hex[i * 2]     = alphabet[v >>> 4];
      hex[i * 2 + 1] = alphabet[v & 0x0f];
    }
    return new String(hex);
  }
}
