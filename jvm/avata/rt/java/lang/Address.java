package java.lang;

public final class Address implements Comparable<Address> {
  public static final int ACCOUNT_ID_BYTES = 32;
  public static final Address ZERO = new Address(0, new byte[ACCOUNT_ID_BYTES],
                                                 false);

  private final int workchain;
  private final byte[] accountId;
  private int hashCode;

  public Address(int workchain, byte[] accountId) {
    this(workchain, accountId, true);
  }

  private Address(int workchain, byte[] accountId, boolean copy) {
    if (accountId.length != ACCOUNT_ID_BYTES) {
      throw new IllegalArgumentException("Address account id requires 32 bytes");
    }
    this.workchain = workchain;
    this.accountId = copy ? ContractHex.copy(accountId) : accountId;
  }

  public static Address fromRaw(int workchain, byte[] accountId) {
    return new Address(workchain, accountId);
  }

  public static Address fromHex(int workchain, String accountIdHex) {
    return new Address(workchain,
                       ContractHex.decodeFixed(accountIdHex, ACCOUNT_ID_BYTES),
                       false);
  }

  public static Address parse(String text) {
    int colon = text.indexOf(':');
    if (colon <= 0 || colon == text.length() - 1) {
      throw new IllegalArgumentException("address must be workchain:hex");
    }
    int wc = Integer.parseInt(text.substring(0, colon));
    return fromHex(wc, text.substring(colon + 1));
  }

  public int workchain() {
    return workchain;
  }

  public Bytes32 accountId() {
    return Bytes32.wrap(ContractHex.copy(accountId));
  }

  public byte[] accountIdBytes() {
    return ContractHex.copy(accountId);
  }

  byte[] rawAccountId() {
    return accountId;
  }

  public boolean isZero() {
    if (workchain != 0) {
      return false;
    }
    for (int i = 0; i < accountId.length; ++i) {
      if (accountId[i] != 0) {
        return false;
      }
    }
    return true;
  }

  public String toString() {
    return String.valueOf(workchain) + ":" + ContractHex.toHex(accountId);
  }

  public int compareTo(Address other) {
    if (workchain != other.workchain) {
      return workchain < other.workchain ? -1 : 1;
    }
    return ContractHex.compareBytes(accountId, other.accountId);
  }

  public boolean equals(Object other) {
    return other instanceof Address
        && workchain == ((Address) other).workchain
        && ContractHex.bytesEqual(accountId, ((Address) other).accountId);
  }

  public int hashCode() {
    if (hashCode == 0) {
      hashCode = 31 * workchain + ContractHex.bytesHash(accountId);
    }
    return hashCode;
  }
}
