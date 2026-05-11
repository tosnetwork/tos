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

  /** ABI-encode `args` into the revert payload using the same rules as
   *  ABI.encode(Object[]) so callers can decode the error symmetrically
   *  via ABI.decode*. */
  protected static void revert(String errorSignature, Object[] args) {
    throw new ContractRevertException(errorSignature,
                                       Bytes.wrap(ABI.encode(args)));
  }

  protected static void requireNonZero(Address address,
                                       String errorSignature) {
    requireCondition(address != null && ! address.isZero(), errorSignature);
  }
}
