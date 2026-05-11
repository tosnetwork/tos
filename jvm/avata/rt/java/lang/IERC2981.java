package java.lang;

public interface IERC2981 extends IERC165 {
  public static final Bytes4 INTERFACE_ID = ABI.interfaceId(new String[] {
    "royaltyInfo(uint256,uint256)"
  });

  RoyaltyInfo royaltyInfo(Uint256 tokenId, Uint256 salePrice);
}
