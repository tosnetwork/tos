package java.lang;

public interface IERC165 {
  public static final Bytes4 INTERFACE_ID = Bytes4.fromHex("01ffc9a7");

  boolean supportsInterface(Bytes4 interfaceId);
}
