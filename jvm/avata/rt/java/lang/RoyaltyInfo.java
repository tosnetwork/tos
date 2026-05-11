package java.lang;

public final class RoyaltyInfo {
  private final Address receiver;
  private final Uint256 royaltyAmount;

  public RoyaltyInfo(Address receiver, Uint256 royaltyAmount) {
    this.receiver = receiver;
    this.royaltyAmount = royaltyAmount;
  }

  public Address receiver() {
    return receiver;
  }

  public Uint256 royaltyAmount() {
    return royaltyAmount;
  }

  public boolean equals(Object other) {
    return other instanceof RoyaltyInfo
        && receiver.equals(((RoyaltyInfo) other).receiver)
        && royaltyAmount.equals(((RoyaltyInfo) other).royaltyAmount);
  }

  public int hashCode() {
    return 31 * receiver.hashCode() + royaltyAmount.hashCode();
  }
}

final class RoyaltySupport {
  private static final Uint256 FEE_DENOMINATOR = Uint256.valueOf(10000);

  private RoyaltySetting defaultRoyalty;
  private final Mapping<Uint256, Address> tokenRoyaltyReceivers;
  private final Mapping<Uint256, Uint256> tokenRoyaltyFeeNumerators;

  RoyaltySupport(Storage storage) {
    tokenRoyaltyReceivers = new Mapping<Uint256, Address>(storage,
        Mapping.namespace("java.lang.RoyaltySupport.tokenRoyaltyReceivers"),
        StorageCodec.ADDRESS);
    tokenRoyaltyFeeNumerators = new Mapping<Uint256, Uint256>(storage,
        Mapping.namespace(
            "java.lang.RoyaltySupport.tokenRoyaltyFeeNumerators"),
        StorageCodec.UINT256);
  }

  Uint256 feeDenominator() {
    return FEE_DENOMINATOR;
  }

  RoyaltyInfo royaltyInfo(Uint256 tokenId, Uint256 salePrice) {
    Address receiver = tokenRoyaltyReceivers.get(tokenId);
    Uint256 feeNumerator;
    if (receiver == null) {
      if (defaultRoyalty == null) {
        return new RoyaltyInfo(Address.ZERO, Uint256.ZERO);
      }
      receiver = defaultRoyalty.receiver;
      feeNumerator = defaultRoyalty.feeNumerator;
    } else {
      feeNumerator = tokenRoyaltyFeeNumerators.getOrDefault(tokenId,
          Uint256.ZERO);
    }

    Uint256 amount = salePrice.multiply(feeNumerator)
        .divide(FEE_DENOMINATOR);
    return new RoyaltyInfo(receiver, amount);
  }

  void setDefaultRoyalty(Address receiver, Uint256 feeNumerator) {
    if (feeNumerator.compareTo(FEE_DENOMINATOR) > 0) {
      Contract.revert(IERC2981Errors.ERC2981_INVALID_DEFAULT_ROYALTY);
    }
    if (receiver == null || receiver.isZero()) {
      Contract.revert(
          IERC2981Errors.ERC2981_INVALID_DEFAULT_ROYALTY_RECEIVER);
    }
    defaultRoyalty = new RoyaltySetting(receiver, feeNumerator);
  }

  void deleteDefaultRoyalty() {
    defaultRoyalty = null;
  }

  void setTokenRoyalty(Uint256 tokenId, Address receiver,
                       Uint256 feeNumerator) {
    if (feeNumerator.compareTo(FEE_DENOMINATOR) > 0) {
      Contract.revert(IERC2981Errors.ERC2981_INVALID_TOKEN_ROYALTY);
    }
    if (receiver == null || receiver.isZero()) {
      Contract.revert(
          IERC2981Errors.ERC2981_INVALID_TOKEN_ROYALTY_RECEIVER);
    }
    tokenRoyaltyReceivers.put(tokenId, receiver);
    tokenRoyaltyFeeNumerators.put(tokenId, feeNumerator);
  }

  void resetTokenRoyalty(Uint256 tokenId) {
    tokenRoyaltyReceivers.remove(tokenId);
    tokenRoyaltyFeeNumerators.remove(tokenId);
  }

  private static final class RoyaltySetting {
    final Address receiver;
    final Uint256 feeNumerator;

    RoyaltySetting(Address receiver, Uint256 feeNumerator) {
      this.receiver = receiver;
      this.feeNumerator = feeNumerator;
    }
  }
}
