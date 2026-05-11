package java.lang;

public interface IERC1155 extends IERC165 {
  public static final Bytes4 INTERFACE_ID = ABI.interfaceId(new String[] {
    "balanceOf(address,uint256)",
    "balanceOfBatch(address[],uint256[])",
    "setApprovalForAll(address,bool)",
    "isApprovedForAll(address,address)",
    "safeTransferFrom(address,address,uint256,uint256,bytes)",
    "safeBatchTransferFrom(address,address,uint256[],uint256[],bytes)"
  });

  Uint256 balanceOf(Address account, Uint256 id);

  Uint256[] balanceOfBatch(Address[] accounts, Uint256[] ids);

  void setApprovalForAll(Address caller, Address operator, boolean approved);

  boolean isApprovedForAll(Address account, Address operator);

  void safeTransferFrom(Address caller, Address from, Address to, Uint256 id,
                        Uint256 value, Bytes data);

  void safeBatchTransferFrom(Address caller, Address from, Address to,
                             Uint256[] ids, Uint256[] values, Bytes data);
}
