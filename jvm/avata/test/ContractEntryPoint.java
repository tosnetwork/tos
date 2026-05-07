public class ContractEntryPoint {
  public static void ok() {
  }

  public static void fail() {
    throw new RuntimeException("contract failed");
  }

  public static void burn() {
    int sum = 0;
    for (int i = 0; i < 100; ++i) {
      sum += i;
    }
    if (sum == 0) {
      throw new RuntimeException();
    }
  }

  public static void args(boolean flag,
                          int value,
                          long wide,
                          Address address,
                          Uint256 amount,
                          Bytes32 bytes32,
                          Bytes4 bytes4,
                          Bytes bytes) {
    if (!flag || value != Integer.MIN_VALUE || wide != Long.MIN_VALUE) {
      throw new RuntimeException("primitive args mismatch");
    }
    if (address.workchain() != -1 || address.accountIdBytes()[31] != 0x7f) {
      throw new RuntimeException("address arg mismatch");
    }
    byte[] amountBytes = amount.toByteArray();
    if (amountBytes[31] != 42) {
      throw new RuntimeException("uint256 arg mismatch");
    }
    if (bytes32.byteAt(0) != 0x11 || bytes32.byteAt(31) != 0x22) {
      throw new RuntimeException("bytes32 arg mismatch");
    }
    if (bytes4.toInt() != 0x01020304) {
      throw new RuntimeException("bytes4 arg mismatch");
    }
    if (bytes.length() != 3 || bytes.byteAt(0) != 7 || bytes.byteAt(2) != 9) {
      throw new RuntimeException("bytes arg mismatch");
    }
  }

  public static void main(String[] args) {
    ok();
    burn();
  }
}
