package java.lang;

public class ERC6909 extends Contract
  implements IERC6909, IERC6909Errors
{
  public static final String INSUFFICIENT_BALANCE =
      IERC6909Errors.ERC6909_INSUFFICIENT_BALANCE;
  public static final String INSUFFICIENT_ALLOWANCE =
      IERC6909Errors.ERC6909_INSUFFICIENT_ALLOWANCE;
  public static final String INVALID_APPROVER =
      IERC6909Errors.ERC6909_INVALID_APPROVER;
  public static final String INVALID_RECEIVER =
      IERC6909Errors.ERC6909_INVALID_RECEIVER;
  public static final String INVALID_SENDER =
      IERC6909Errors.ERC6909_INVALID_SENDER;
  public static final String INVALID_SPENDER =
      IERC6909Errors.ERC6909_INVALID_SPENDER;

  private final Bytes32 balancesNamespace =
      Mapping.namespace("java.lang.ERC6909.balances");
  private final Bytes32 operatorsNamespace =
      Mapping.namespace("java.lang.ERC6909.operators");
  private final Bytes32 allowancesNamespace =
      Mapping.namespace("java.lang.ERC6909.allowances");

  public boolean supportsInterface(Bytes4 interfaceId) {
    return interfaceId.equals(IERC165.INTERFACE_ID)
        || interfaceId.equals(IERC6909.INTERFACE_ID);
  }

  public Uint256 balanceOf(Address owner, Uint256 id) {
    return balanceMap(owner).getOrDefault(id, Uint256.ZERO);
  }

  public Uint256 allowance(Address owner, Address spender, Uint256 id) {
    return allowanceMap(owner, spender).getOrDefault(id, Uint256.ZERO);
  }

  public boolean isOperator(Address owner, Address spender) {
    return operatorMap(owner).getOrDefault(spender, Boolean.FALSE)
        .booleanValue();
  }

  public boolean approve(Address caller, Address spender, Uint256 id,
                         Uint256 amount) {
    approveInternal(caller, spender, id, amount);
    return true;
  }

  public boolean setOperator(Address caller, Address spender,
                             boolean approved) {
    setOperatorInternal(caller, spender, approved);
    return true;
  }

  public boolean transfer(Address caller, Address receiver, Uint256 id,
                          Uint256 amount) {
    transferInternal(caller, receiver, id, amount);
    return true;
  }

  public boolean transferFrom(Address caller, Address sender, Address receiver,
                              Uint256 id, Uint256 amount) {
    if (! equalsAddress(sender, caller) && ! isOperator(sender, caller)) {
      spendAllowance(sender, caller, id, amount);
    }
    transferInternal(sender, receiver, id, amount);
    return true;
  }

  protected void mint(Address to, Uint256 id, Uint256 amount) {
    if (isZero(to)) {
      revert(INVALID_RECEIVER);
    }
    update(Address.ZERO, to, id, amount);
  }

  protected void burn(Address from, Uint256 id, Uint256 amount) {
    if (isZero(from)) {
      revert(INVALID_SENDER);
    }
    update(from, Address.ZERO, id, amount);
  }

  protected void transferInternal(Address from, Address to, Uint256 id,
                                  Uint256 amount) {
    if (isZero(from)) {
      revert(INVALID_SENDER);
    }
    if (isZero(to)) {
      revert(INVALID_RECEIVER);
    }
    update(from, to, id, amount);
  }

  protected void update(Address from, Address to, Uint256 id, Uint256 amount) {
    if (! isZero(from)) {
      Uint256 fromBalance = balanceOf(from, id);
      if (fromBalance.compareTo(amount) < 0) {
        revert(INSUFFICIENT_BALANCE);
      }
      setBalance(from, id, fromBalance.subtract(amount));
    }

    if (! isZero(to)) {
      setBalance(to, id, balanceOf(to, id).add(amount));
    }
  }

  protected void approveInternal(Address owner, Address spender, Uint256 id,
                                 Uint256 amount) {
    if (isZero(owner)) {
      revert(INVALID_APPROVER);
    }
    if (isZero(spender)) {
      revert(INVALID_SPENDER);
    }
    allowanceMap(owner, spender).put(id, amount);
  }

  protected void setOperatorInternal(Address owner, Address spender,
                                     boolean approved) {
    if (isZero(owner)) {
      revert(INVALID_APPROVER);
    }
    if (isZero(spender)) {
      revert(INVALID_SPENDER);
    }
    if (approved) {
      operatorMap(owner).put(spender, Boolean.TRUE);
    } else {
      operatorMap(owner).remove(spender);
    }
  }

  protected void spendAllowance(Address owner, Address spender, Uint256 id,
                                Uint256 amount) {
    Uint256 current = allowance(owner, spender, id);
    if (current.isMaxValue()) {
      return;
    }
    if (current.compareTo(amount) < 0) {
      revert(INSUFFICIENT_ALLOWANCE);
    }
    allowanceMap(owner, spender).put(id, current.subtract(amount));
  }

  private void setBalance(Address owner, Uint256 id, Uint256 value) {
    Mapping<Uint256, Uint256> ownerBalances = balanceMap(owner);
    if (value.isZero()) {
      ownerBalances.remove(id);
    } else {
      ownerBalances.put(id, value);
    }
  }

  private Mapping<Uint256, Uint256> balanceMap(Address owner) {
    return new Mapping<Uint256, Uint256>(storage(),
        Mapping.slot(balancesNamespace, owner), StorageCodec.UINT256);
  }

  private Mapping<Address, Boolean> operatorMap(Address owner) {
    return new Mapping<Address, Boolean>(storage(),
        Mapping.slot(operatorsNamespace, owner), StorageCodec.BOOLEAN);
  }

  private Mapping<Uint256, Uint256> allowanceMap(Address owner,
                                                Address spender) {
    Bytes32 ownerNamespace = Mapping.slot(allowancesNamespace, owner);
    return new Mapping<Uint256, Uint256>(storage(),
        Mapping.slot(ownerNamespace, spender), StorageCodec.UINT256);
  }

  private static boolean equalsAddress(Address first, Address second) {
    return first == null ? second == null : first.equals(second);
  }

  protected static boolean isZero(Address address) {
    return address == null || address.isZero();
  }
}
