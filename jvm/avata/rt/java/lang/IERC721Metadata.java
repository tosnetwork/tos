package java.lang;

public interface IERC721Metadata extends IERC721 {
  public static final Bytes4 INTERFACE_ID = ABI.interfaceId(new String[] {
    "name()",
    "symbol()",
    "tokenURI(uint256)"
  });

  String name();

  String symbol();

  String tokenURI(Uint256 tokenId);
}
