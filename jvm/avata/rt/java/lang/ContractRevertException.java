package java.lang;

public final class ContractRevertException extends RuntimeException {
  private final String signature;
  private final Bytes4 selector;
  private final Bytes data;

  public ContractRevertException(String signature) {
    this(signature, Bytes.EMPTY);
  }

  public ContractRevertException(String signature, Bytes data) {
    super(signature);
    this.signature = signature;
    this.selector = ABI.selector(signature);
    this.data = data;
  }

  public String signature() {
    return signature;
  }

  public Bytes4 selector() {
    return selector;
  }

  public Bytes data() {
    return data;
  }

  public byte[] encoded() {
    return ABI.concat(selector.toByteArray(), data.toByteArray());
  }
}
