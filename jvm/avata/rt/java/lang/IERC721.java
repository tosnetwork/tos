package java.lang;

public interface IERC721 extends IERC165 {
  public static final Bytes4 INTERFACE_ID = ABI.interfaceId(new String[] {
    "balanceOf(address)",
    "ownerOf(uint256)",
    "safeTransferFrom(address,address,uint256)",
    "transferFrom(address,address,uint256)",
    "approve(address,uint256)",
    "setApprovalForAll(address,bool)",
    "getApproved(uint256)",
    "isApprovedForAll(address,address)",
    "safeTransferFrom(address,address,uint256,bytes)"
  });

  Uint256 balanceOf(Address owner);

  Address ownerOf(Uint256 tokenId);

  void safeTransferFrom(Address caller, Address from, Address to,
                        Uint256 tokenId);

  void safeTransferFrom(Address caller, Address from, Address to,
                        Uint256 tokenId, Bytes data);

  void transferFrom(Address caller, Address from, Address to, Uint256 tokenId);

  void approve(Address caller, Address to, Uint256 tokenId);

  void setApprovalForAll(Address caller, Address operator, boolean approved);

  Address getApproved(Uint256 tokenId);

  boolean isApprovedForAll(Address owner, Address operator);
}
