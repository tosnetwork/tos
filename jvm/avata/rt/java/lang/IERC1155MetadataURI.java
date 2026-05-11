package java.lang;

public interface IERC1155MetadataURI extends IERC1155 {
  public static final Bytes4 INTERFACE_ID = ABI.interfaceId(new String[] {
    "uri(uint256)"
  });

  String uri(Uint256 id);
}
