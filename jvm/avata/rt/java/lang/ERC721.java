package java.lang;

public class ERC721 extends Contract
  implements IERC721Metadata, IERC721Errors
{
  public static final String INVALID_OWNER =
      IERC721Errors.ERC721_INVALID_OWNER;
  public static final String NONEXISTENT_TOKEN =
      IERC721Errors.ERC721_NONEXISTENT_TOKEN;
  public static final String INCORRECT_OWNER =
      IERC721Errors.ERC721_INCORRECT_OWNER;
  public static final String INVALID_SENDER =
      IERC721Errors.ERC721_INVALID_SENDER;
  public static final String INVALID_RECEIVER =
      IERC721Errors.ERC721_INVALID_RECEIVER;
  public static final String INSUFFICIENT_APPROVAL =
      IERC721Errors.ERC721_INSUFFICIENT_APPROVAL;
  public static final String INVALID_APPROVER =
      IERC721Errors.ERC721_INVALID_APPROVER;
  public static final String INVALID_OPERATOR =
      IERC721Errors.ERC721_INVALID_OPERATOR;

  private final String name;
  private final String symbol;
  private final Mapping<Uint256, Address> owners =
      new Mapping<Uint256, Address>(
          storage(),
          Mapping.namespace("java.lang.ERC721.owners"),
          StorageCodec.ADDRESS);
  private final Mapping<Address, Uint256> balances =
      new Mapping<Address, Uint256>(
          storage(),
          Mapping.namespace("java.lang.ERC721.balances"),
          StorageCodec.UINT256);
  private final Mapping<Uint256, Address> tokenApprovals =
      new Mapping<Uint256, Address>(
          storage(),
          Mapping.namespace("java.lang.ERC721.tokenApprovals"),
          StorageCodec.ADDRESS);
  private final Bytes32 operatorApprovalsNamespace =
      Mapping.namespace("java.lang.ERC721.operatorApprovals");

  public ERC721(String name, String symbol) {
    this.name = name;
    this.symbol = symbol;
  }

  public boolean supportsInterface(Bytes4 interfaceId) {
    return interfaceId.equals(IERC165.INTERFACE_ID)
        || interfaceId.equals(IERC721.INTERFACE_ID)
        || interfaceId.equals(IERC721Metadata.INTERFACE_ID);
  }

  public final String name() {
    return name;
  }

  public final String symbol() {
    return symbol;
  }

  public String tokenURI(Uint256 tokenId) {
    requireOwned(tokenId);
    String base = baseURI();
    return base.length() == 0 ? "" : base + tokenId.toString();
  }

  protected String baseURI() {
    return "";
  }

  public Uint256 balanceOf(Address owner) {
    if (isZero(owner)) {
      revert(INVALID_OWNER);
    }
    return balanceOfOrZero(owner);
  }

  public Address ownerOf(Uint256 tokenId) {
    return requireOwned(tokenId);
  }

  public Address getApproved(Uint256 tokenId) {
    requireOwned(tokenId);
    Address approved = tokenApprovals.get(tokenId);
    return approved == null ? Address.ZERO : approved;
  }

  public boolean isApprovedForAll(Address owner, Address operator) {
    return operatorApprovalMap(owner).getOrDefault(operator, Boolean.FALSE)
        .booleanValue();
  }

  public void approve(Address caller, Address to, Uint256 tokenId) {
    approveInternal(to, tokenId, caller);
  }

  public void setApprovalForAll(Address caller, Address operator,
                                boolean approved) {
    if (isZero(caller)) {
      revert(INVALID_APPROVER);
    }
    if (isZero(operator)) {
      revert(INVALID_OPERATOR);
    }

    if (approved) {
      operatorApprovalMap(caller).put(operator, Boolean.TRUE);
    } else {
      operatorApprovalMap(caller).remove(operator);
    }
  }

  public void transferFrom(Address caller, Address from, Address to,
                           Uint256 tokenId) {
    transferAuthorized(caller, from, to, tokenId);
  }

  public void safeTransferFrom(Address caller, Address from, Address to,
                               Uint256 tokenId) {
    safeTransferFrom(caller, from, to, tokenId, Bytes.EMPTY);
  }

  public void safeTransferFrom(Address caller, Address from, Address to,
                               Uint256 tokenId, Bytes data) {
    transferAuthorized(caller, from, to, tokenId);
  }

  protected void mint(Address to, Uint256 tokenId) {
    if (isZero(to)) {
      revert(INVALID_RECEIVER);
    }
    if (! ownerOfOrZero(tokenId).isZero()) {
      revert(INVALID_SENDER);
    }
    owners.put(tokenId, to);
    increaseBalance(to);
  }

  protected void burn(Uint256 tokenId) {
    Address owner = requireOwned(tokenId);
    clearApproval(tokenId);
    owners.remove(tokenId);
    decreaseBalance(owner);
  }

  protected void transferInternal(Address from, Address to, Uint256 tokenId) {
    if (isZero(to)) {
      revert(INVALID_RECEIVER);
    }
    Address owner = requireOwned(tokenId);
    if (! owner.equals(from)) {
      revert(INCORRECT_OWNER);
    }
    clearApproval(tokenId);
    owners.put(tokenId, to);
    decreaseBalance(owner);
    increaseBalance(to);
  }

  protected boolean isAuthorized(Address owner, Address spender,
                                 Uint256 tokenId) {
    return ! isZero(spender)
        && (owner.equals(spender)
            || isApprovedForAll(owner, spender)
            || getApprovedOrZero(tokenId).equals(spender));
  }

  protected void checkAuthorized(Address owner, Address spender,
                                 Uint256 tokenId) {
    if (! isAuthorized(owner, spender, tokenId)) {
      if (owner.isZero()) {
        revert(NONEXISTENT_TOKEN);
      }
      revert(INSUFFICIENT_APPROVAL);
    }
  }

  private void transferAuthorized(Address caller, Address from, Address to,
                                  Uint256 tokenId) {
    if (isZero(to)) {
      revert(INVALID_RECEIVER);
    }
    Address owner = requireOwned(tokenId);
    checkAuthorized(owner, caller, tokenId);
    if (! owner.equals(from)) {
      revert(INCORRECT_OWNER);
    }
    clearApproval(tokenId);
    owners.put(tokenId, to);
    decreaseBalance(owner);
    increaseBalance(to);
  }

  private void approveInternal(Address to, Uint256 tokenId, Address caller) {
    Address owner = requireOwned(tokenId);
    if (! owner.equals(caller) && ! isApprovedForAll(owner, caller)) {
      revert(INVALID_APPROVER);
    }

    if (isZero(to)) {
      clearApproval(tokenId);
    } else {
      tokenApprovals.put(tokenId, to);
    }
  }

  private Address requireOwned(Uint256 tokenId) {
    Address owner = ownerOfOrZero(tokenId);
    if (owner.isZero()) {
      revert(NONEXISTENT_TOKEN);
    }
    return owner;
  }

  private Address ownerOfOrZero(Uint256 tokenId) {
    Address owner = owners.get(tokenId);
    return owner == null ? Address.ZERO : owner;
  }

  private Address getApprovedOrZero(Uint256 tokenId) {
    Address approved = tokenApprovals.get(tokenId);
    return approved == null ? Address.ZERO : approved;
  }

  private Uint256 balanceOfOrZero(Address owner) {
    Uint256 balance = balances.get(owner);
    return balance == null ? Uint256.ZERO : balance;
  }

  private void increaseBalance(Address owner) {
    balances.put(owner, balanceOfOrZero(owner).add(Uint256.ONE));
  }

  private void decreaseBalance(Address owner) {
    Uint256 balance = balanceOfOrZero(owner).subtract(Uint256.ONE);
    if (balance.isZero()) {
      balances.remove(owner);
    } else {
      balances.put(owner, balance);
    }
  }

  private void clearApproval(Uint256 tokenId) {
    tokenApprovals.remove(tokenId);
  }

  private Mapping<Address, Boolean> operatorApprovalMap(Address owner) {
    return new Mapping<Address, Boolean>(storage(),
        Mapping.slot(operatorApprovalsNamespace, owner),
        StorageCodec.BOOLEAN);
  }

  private static boolean isZero(Address address) {
    return address == null || address.isZero();
  }
}
