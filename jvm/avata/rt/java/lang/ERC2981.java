package java.lang;

public class ERC2981 extends Contract implements IERC2981, IERC2981Errors {
  public static final String INVALID_DEFAULT_ROYALTY =
      IERC2981Errors.ERC2981_INVALID_DEFAULT_ROYALTY;
  public static final String INVALID_DEFAULT_ROYALTY_RECEIVER =
      IERC2981Errors.ERC2981_INVALID_DEFAULT_ROYALTY_RECEIVER;
  public static final String INVALID_TOKEN_ROYALTY =
      IERC2981Errors.ERC2981_INVALID_TOKEN_ROYALTY;
  public static final String INVALID_TOKEN_ROYALTY_RECEIVER =
      IERC2981Errors.ERC2981_INVALID_TOKEN_ROYALTY_RECEIVER;

  private final RoyaltySupport royalties = new RoyaltySupport(storage());

  public boolean supportsInterface(Bytes4 interfaceId) {
    return interfaceId.equals(IERC165.INTERFACE_ID)
        || interfaceId.equals(IERC2981.INTERFACE_ID);
  }

  public RoyaltyInfo royaltyInfo(Uint256 tokenId, Uint256 salePrice) {
    return royalties.royaltyInfo(tokenId, salePrice);
  }

  protected Uint256 feeDenominator() {
    return royalties.feeDenominator();
  }

  protected void setDefaultRoyalty(Address receiver, Uint256 feeNumerator) {
    royalties.setDefaultRoyalty(receiver, feeNumerator);
  }

  protected void deleteDefaultRoyalty() {
    royalties.deleteDefaultRoyalty();
  }

  protected void setTokenRoyalty(Uint256 tokenId, Address receiver,
                                 Uint256 feeNumerator) {
    royalties.setTokenRoyalty(tokenId, receiver, feeNumerator);
  }

  protected void resetTokenRoyalty(Uint256 tokenId) {
    royalties.resetTokenRoyalty(tokenId);
  }
}
