package java.lang;

public interface IERC20Metadata extends IERC20 {
  public static final Bytes4 INTERFACE_ID = ABI.interfaceId(new String[] {
    "name()",
    "symbol()",
    "decimals()"
  });

  String name();

  String symbol();

  int decimals();
}
