package java.lang;

public interface IERC6909ContentURI extends IERC6909 {
  public static final Bytes4 INTERFACE_ID = ABI.interfaceId(new String[] {
    "contractURI()",
    "tokenURI(uint256)"
  });

  String contractURI();

  String tokenURI(Uint256 id);
}
