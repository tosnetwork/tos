package java.lang;

public class ERC1155Holder extends Contract implements IERC1155Receiver {
  public boolean supportsInterface(Bytes4 interfaceId) {
    return interfaceId.equals(IERC165.INTERFACE_ID)
        || interfaceId.equals(IERC1155Receiver.INTERFACE_ID);
  }

  public Bytes4 onERC1155Received(Address operator, Address from, Uint256 id,
                                  Uint256 value, Bytes data) {
    return IERC1155Receiver.ON_ERC1155_RECEIVED_SELECTOR;
  }

  public Bytes4 onERC1155BatchReceived(Address operator, Address from,
                                       Uint256[] ids, Uint256[] values,
                                       Bytes data) {
    return IERC1155Receiver.ON_ERC1155_BATCH_RECEIVED_SELECTOR;
  }
}
