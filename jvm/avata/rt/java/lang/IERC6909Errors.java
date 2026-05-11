package java.lang;

public interface IERC6909Errors {
  public static final String ERC6909_INSUFFICIENT_BALANCE =
      "ERC6909InsufficientBalance(address,uint256,uint256,uint256)";
  public static final String ERC6909_INSUFFICIENT_ALLOWANCE =
      "ERC6909InsufficientAllowance(address,uint256,uint256,uint256)";
  public static final String ERC6909_INVALID_APPROVER =
      "ERC6909InvalidApprover(address)";
  public static final String ERC6909_INVALID_RECEIVER =
      "ERC6909InvalidReceiver(address)";
  public static final String ERC6909_INVALID_SENDER =
      "ERC6909InvalidSender(address)";
  public static final String ERC6909_INVALID_SPENDER =
      "ERC6909InvalidSpender(address)";
}
