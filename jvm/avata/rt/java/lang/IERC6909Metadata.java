package java.lang;

public interface IERC6909Metadata extends IERC6909 {
  public static final Bytes4 INTERFACE_ID = ABI.interfaceId(new String[] {
    "name(uint256)",
    "symbol(uint256)",
    "decimals(uint256)"
  });

  String name(Uint256 id);

  String symbol(Uint256 id);

  int decimals(Uint256 id);
}
