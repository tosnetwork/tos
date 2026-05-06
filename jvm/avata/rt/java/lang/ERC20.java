package java.lang;

public class ERC20 extends Contract
  implements IERC20Metadata, IERC20Errors
{
  public static final String INSUFFICIENT_BALANCE =
      IERC20Errors.ERC20_INSUFFICIENT_BALANCE;
  public static final String INSUFFICIENT_ALLOWANCE =
      IERC20Errors.ERC20_INSUFFICIENT_ALLOWANCE;
  public static final String INVALID_SENDER =
      IERC20Errors.ERC20_INVALID_SENDER;
  public static final String INVALID_RECEIVER =
      IERC20Errors.ERC20_INVALID_RECEIVER;
  public static final String INVALID_APPROVER =
      IERC20Errors.ERC20_INVALID_APPROVER;
  public static final String INVALID_SPENDER =
      IERC20Errors.ERC20_INVALID_SPENDER;

  private final String name;
  private final String symbol;
  private final int decimals;
  private Uint256 totalSupply = Uint256.ZERO;
  private final Mapping<Address, Uint256> balances =
      new Mapping<Address, Uint256>(storage(),
          Mapping.namespace("java.lang.ERC20.balances"),
          StorageCodec.UINT256);
  private final Bytes32 allowancesNamespace =
      Mapping.namespace("java.lang.ERC20.allowances");

  public ERC20(String name, String symbol) {
    this(name, symbol, 18);
  }

  public ERC20(String name, String symbol, int decimals) {
    if (decimals < 0) {
      throw new IllegalArgumentException("decimals must be non-negative");
    }
    this.name = name;
    this.symbol = symbol;
    this.decimals = decimals;
  }

  public final String name() {
    return name;
  }

  public final String symbol() {
    return symbol;
  }

  public int decimals() {
    return decimals;
  }

  public final Uint256 totalSupply() {
    return totalSupply;
  }

  public Uint256 balanceOf(Address account) {
    return balances.getOrDefault(account, Uint256.ZERO);
  }

  public Uint256 allowance(Address owner, Address spender) {
    return allowanceMap(owner).getOrDefault(spender, Uint256.ZERO);
  }

  public boolean transfer(Address caller, Address to, Uint256 value) {
    transferInternal(caller, to, value);
    return true;
  }

  public boolean approve(Address caller, Address spender, Uint256 value) {
    approveInternal(caller, spender, value);
    return true;
  }

  public boolean transferFrom(Address caller, Address from, Address to,
                              Uint256 value) {
    spendAllowance(from, caller, value);
    transferInternal(from, to, value);
    return true;
  }

  protected void mint(Address account, Uint256 value) {
    if (account == null || account.isZero()) {
      revert(INVALID_RECEIVER);
    }
    totalSupply = totalSupply.add(value);
    balances.put(account, balanceOf(account).add(value));
  }

  protected void burn(Address account, Uint256 value) {
    if (account == null || account.isZero()) {
      revert(INVALID_SENDER);
    }
    Uint256 balance = balanceOf(account);
    if (balance.compareTo(value) < 0) {
      revert(INSUFFICIENT_BALANCE);
    }
    balances.put(account, balance.subtract(value));
    totalSupply = totalSupply.subtract(value);
  }

  protected void transferInternal(Address from, Address to, Uint256 value) {
    if (from == null || from.isZero()) {
      revert(INVALID_SENDER);
    }
    if (to == null || to.isZero()) {
      revert(INVALID_RECEIVER);
    }

    Uint256 fromBalance = balanceOf(from);
    if (fromBalance.compareTo(value) < 0) {
      revert(INSUFFICIENT_BALANCE);
    }

    balances.put(from, fromBalance.subtract(value));
    balances.put(to, balanceOf(to).add(value));
  }

  protected void approveInternal(Address owner, Address spender,
                                 Uint256 value) {
    if (owner == null || owner.isZero()) {
      revert(INVALID_APPROVER);
    }
    if (spender == null || spender.isZero()) {
      revert(INVALID_SPENDER);
    }
    allowanceMap(owner).put(spender, value);
  }

  protected void spendAllowance(Address owner, Address spender, Uint256 value) {
    Uint256 current = allowance(owner, spender);
    if (current.isMaxValue()) {
      return;
    }
    if (current.compareTo(value) < 0) {
      revert(INSUFFICIENT_ALLOWANCE);
    }
    approveInternal(owner, spender, current.subtract(value));
  }

  private Mapping<Address, Uint256> allowanceMap(Address owner) {
    return new Mapping<Address, Uint256>(storage(),
        Mapping.slot(allowancesNamespace, owner), StorageCodec.UINT256);
  }
}
