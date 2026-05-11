package java.internal;

public final class BootProfile {
  private BootProfile() { }

  public static void initializeForContract() {
    System.getProperty("line.separator");
    Boolean.TRUE.booleanValue();
    Boolean.FALSE.booleanValue();
    Byte.valueOf((byte) 0).byteValue();
    Short.valueOf((short) 0).shortValue();
    Character.valueOf('0').charValue();
    Integer.valueOf(0).intValue();
    Long.valueOf(0L).longValue();
    Float.valueOf(0.0f).floatValue();
    Double.valueOf(0.0d).doubleValue();
    Bytes.EMPTY.toByteArray();
    Bytes4.ZERO.toByteArray();
    Bytes32.ZERO.toByteArray();
    Uint256.ZERO.toByteArray();
    Address.ZERO.accountIdBytes();
  }
}
