package java.lang;

public interface IERC1155Receiver extends IERC165 {
  public static final Bytes4 ON_ERC1155_RECEIVED_SELECTOR = ABI.selector(
      "onERC1155Received(address,address,uint256,uint256,bytes)");
  public static final Bytes4 ON_ERC1155_BATCH_RECEIVED_SELECTOR =
      ABI.selector(
          "onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)");
  public static final Bytes4 INTERFACE_ID = ABI.interfaceId(new String[] {
    "onERC1155Received(address,address,uint256,uint256,bytes)",
    "onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"
  });

  Bytes4 onERC1155Received(Address operator, Address from, Uint256 id,
                           Uint256 value, Bytes data);

  Bytes4 onERC1155BatchReceived(Address operator, Address from, Uint256[] ids,
                                Uint256[] values, Bytes data);
}
