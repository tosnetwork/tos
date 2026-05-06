package java.lang;

public interface IERC20Errors {
  public static final String ERC20_INSUFFICIENT_BALANCE =
      "ERC20InsufficientBalance(address,uint256,uint256)";
  public static final String ERC20_INVALID_SENDER =
      "ERC20InvalidSender(address)";
  public static final String ERC20_INVALID_RECEIVER =
      "ERC20InvalidReceiver(address)";
  public static final String ERC20_INSUFFICIENT_ALLOWANCE =
      "ERC20InsufficientAllowance(address,uint256,uint256)";
  public static final String ERC20_INVALID_APPROVER =
      "ERC20InvalidApprover(address)";
  public static final String ERC20_INVALID_SPENDER =
      "ERC20InvalidSpender(address)";
}
