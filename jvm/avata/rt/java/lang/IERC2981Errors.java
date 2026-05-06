package java.lang;

public interface IERC2981Errors {
  public static final String ERC2981_INVALID_DEFAULT_ROYALTY =
      "ERC2981InvalidDefaultRoyalty(uint256,uint256)";
  public static final String ERC2981_INVALID_DEFAULT_ROYALTY_RECEIVER =
      "ERC2981InvalidDefaultRoyaltyReceiver(address)";
  public static final String ERC2981_INVALID_TOKEN_ROYALTY =
      "ERC2981InvalidTokenRoyalty(uint256,uint256,uint256)";
  public static final String ERC2981_INVALID_TOKEN_ROYALTY_RECEIVER =
      "ERC2981InvalidTokenRoyaltyReceiver(uint256,address)";
}
