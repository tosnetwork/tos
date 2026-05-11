package java.lang;

public interface IERC6909TokenSupply extends IERC6909 {
  public static final Bytes4 INTERFACE_ID = ABI.interfaceId(new String[] {
    "totalSupply(uint256)"
  });

  Uint256 totalSupply(Uint256 id);
}
