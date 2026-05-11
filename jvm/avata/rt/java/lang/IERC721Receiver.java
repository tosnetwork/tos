package java.lang;

public interface IERC721Receiver {
  public static final Bytes4 ON_ERC721_RECEIVED_SELECTOR = ABI.selector(
      "onERC721Received(address,address,uint256,bytes)");

  Bytes4 onERC721Received(Address operator, Address from, Uint256 tokenId,
                          Bytes data);
}
