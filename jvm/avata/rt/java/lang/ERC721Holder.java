package java.lang;

public class ERC721Holder extends Contract implements IERC721Receiver {
  public Bytes4 onERC721Received(Address operator, Address from,
                                 Uint256 tokenId, Bytes data) {
    return IERC721Receiver.ON_ERC721_RECEIVED_SELECTOR;
  }
}
