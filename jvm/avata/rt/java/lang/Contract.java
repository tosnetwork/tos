package java.lang;

public abstract class Contract {
  private final Storage storage = Storage.current();

  protected Contract() { }

  protected final Storage storage() {
    return storage;
  }

  protected static void requireCondition(boolean condition,
                                         String errorSignature) {
    if (! condition) {
      revert(errorSignature);
    }
  }

  protected static void revert(String errorSignature) {
    throw new ContractRevertException(errorSignature);
  }

  protected static void revert(String errorSignature, Bytes data) {
    throw new ContractRevertException(errorSignature, data);
  }

  protected static void requireNonZero(Address address,
                                       String errorSignature) {
    requireCondition(address != null && ! address.isZero(), errorSignature);
  }
}
