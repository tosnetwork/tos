package java.lang;

public class ERC1155 extends Contract
  implements IERC1155MetadataURI, IERC1155Errors
{
  public static final String INSUFFICIENT_BALANCE =
      IERC1155Errors.ERC1155_INSUFFICIENT_BALANCE;
  public static final String INVALID_SENDER =
      IERC1155Errors.ERC1155_INVALID_SENDER;
  public static final String INVALID_RECEIVER =
      IERC1155Errors.ERC1155_INVALID_RECEIVER;
  public static final String MISSING_APPROVAL_FOR_ALL =
      IERC1155Errors.ERC1155_MISSING_APPROVAL_FOR_ALL;
  public static final String INVALID_APPROVER =
      IERC1155Errors.ERC1155_INVALID_APPROVER;
  public static final String INVALID_OPERATOR =
      IERC1155Errors.ERC1155_INVALID_OPERATOR;
  public static final String INVALID_ARRAY_LENGTH =
      IERC1155Errors.ERC1155_INVALID_ARRAY_LENGTH;

  private String uri;
  private final Bytes32 balancesNamespace =
      Mapping.namespace("java.lang.ERC1155.balances");
  private final Bytes32 operatorApprovalsNamespace =
      Mapping.namespace("java.lang.ERC1155.operatorApprovals");

  public ERC1155(String uri) {
    this.uri = uri;
  }

  public boolean supportsInterface(Bytes4 interfaceId) {
    return interfaceId.equals(IERC165.INTERFACE_ID)
        || interfaceId.equals(IERC1155.INTERFACE_ID)
        || interfaceId.equals(IERC1155MetadataURI.INTERFACE_ID);
  }

  public String uri(Uint256 id) {
    return uri;
  }

  public Uint256 balanceOf(Address account, Uint256 id) {
    return balanceOfOrZero(account, id);
  }

  public Uint256[] balanceOfBatch(Address[] accounts, Uint256[] ids) {
    if (accounts.length != ids.length) {
      revert(INVALID_ARRAY_LENGTH);
    }
    Uint256[] out = new Uint256[accounts.length];
    for (int i = 0; i < accounts.length; ++i) {
      out[i] = balanceOf(accounts[i], ids[i]);
    }
    return out;
  }

  public void setApprovalForAll(Address caller, Address operator,
                                boolean approved) {
    setApprovalForAllInternal(caller, operator, approved);
  }

  public boolean isApprovedForAll(Address account, Address operator) {
    return operatorApprovalMap(account).getOrDefault(operator, Boolean.FALSE)
        .booleanValue();
  }

  public void safeTransferFrom(Address caller, Address from, Address to,
                               Uint256 id, Uint256 value, Bytes data) {
    checkAuthorized(caller, from);
    safeTransferFromInternal(from, to, id, value);
  }

  public void safeBatchTransferFrom(Address caller, Address from, Address to,
                                    Uint256[] ids, Uint256[] values,
                                    Bytes data) {
    checkAuthorized(caller, from);
    safeBatchTransferFromInternal(from, to, ids, values);
  }

  protected void setURI(String uri) {
    this.uri = uri;
  }

  protected void mint(Address to, Uint256 id, Uint256 value) {
    if (isZero(to)) {
      revert(INVALID_RECEIVER);
    }
    update(Address.ZERO, to, singleton(id), singleton(value));
  }

  protected void mintBatch(Address to, Uint256[] ids, Uint256[] values) {
    if (isZero(to)) {
      revert(INVALID_RECEIVER);
    }
    update(Address.ZERO, to, ids, values);
  }

  protected void burn(Address from, Uint256 id, Uint256 value) {
    if (isZero(from)) {
      revert(INVALID_SENDER);
    }
    update(from, Address.ZERO, singleton(id), singleton(value));
  }

  protected void burnBatch(Address from, Uint256[] ids, Uint256[] values) {
    if (isZero(from)) {
      revert(INVALID_SENDER);
    }
    update(from, Address.ZERO, ids, values);
  }

  protected void safeTransferFromInternal(Address from, Address to,
                                          Uint256 id, Uint256 value) {
    if (isZero(to)) {
      revert(INVALID_RECEIVER);
    }
    if (isZero(from)) {
      revert(INVALID_SENDER);
    }
    update(from, to, singleton(id), singleton(value));
  }

  protected void safeBatchTransferFromInternal(Address from, Address to,
                                               Uint256[] ids,
                                               Uint256[] values) {
    if (isZero(to)) {
      revert(INVALID_RECEIVER);
    }
    if (isZero(from)) {
      revert(INVALID_SENDER);
    }
    update(from, to, ids, values);
  }

  protected void checkAuthorized(Address operator, Address owner) {
    if (! equalsAddress(owner, operator) && ! isApprovedForAll(owner, operator)) {
      revert(MISSING_APPROVAL_FOR_ALL);
    }
  }

  private void update(Address from, Address to, Uint256[] ids,
                      Uint256[] values) {
    if (ids.length != values.length) {
      revert(INVALID_ARRAY_LENGTH);
    }

    for (int i = 0; i < ids.length; ++i) {
      if (! isZero(from)
          && balanceOfOrZero(from, ids[i]).compareTo(values[i]) < 0) {
        revert(INSUFFICIENT_BALANCE);
      }
    }

    for (int i = 0; i < ids.length; ++i) {
      Uint256 id = ids[i];
      Uint256 value = values[i];

      if (! isZero(from)) {
        setBalance(from, id, balanceOfOrZero(from, id).subtract(value));
      }

      if (! isZero(to)) {
        setBalance(to, id, balanceOfOrZero(to, id).add(value));
      }
    }
  }

  private void setApprovalForAllInternal(Address owner, Address operator,
                                         boolean approved) {
    if (isZero(owner)) {
      revert(INVALID_APPROVER);
    }
    if (isZero(operator)) {
      revert(INVALID_OPERATOR);
    }

    if (approved) {
      operatorApprovalMap(owner).put(operator, Boolean.TRUE);
    } else {
      operatorApprovalMap(owner).remove(operator);
    }
  }

  private Uint256 balanceOfOrZero(Address account, Uint256 id) {
    return balanceMap(id).getOrDefault(account, Uint256.ZERO);
  }

  private void setBalance(Address account, Uint256 id, Uint256 value) {
    Mapping<Address, Uint256> byAccount = balanceMap(id);
    if (value.isZero()) {
      byAccount.remove(account);
    } else {
      byAccount.put(account, value);
    }
  }

  private Mapping<Address, Uint256> balanceMap(Uint256 id) {
    return new Mapping<Address, Uint256>(storage(),
        Mapping.slot(balancesNamespace, id), StorageCodec.UINT256);
  }

  private Mapping<Address, Boolean> operatorApprovalMap(Address owner) {
    return new Mapping<Address, Boolean>(storage(),
        Mapping.slot(operatorApprovalsNamespace, owner),
        StorageCodec.BOOLEAN);
  }

  private static Uint256[] singleton(Uint256 value) {
    return new Uint256[] { value };
  }

  private static boolean equalsAddress(Address first, Address second) {
    return first == null ? second == null : first.equals(second);
  }

  private static boolean isZero(Address address) {
    return address == null || address.isZero();
  }
}
