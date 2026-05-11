package java.lang;

public class Ownable extends Contract implements IERC5313 {
  public static final String UNAUTHORIZED =
      "OwnableUnauthorizedAccount(address)";
  public static final String INVALID_OWNER = "OwnableInvalidOwner(address)";

  private Address owner;

  public Ownable(Address initialOwner) {
    requireNonZero(initialOwner, INVALID_OWNER);
    transferOwnershipInternal(initialOwner);
  }

  public final Address owner() {
    return owner;
  }

  public final boolean isOwner(Address account) {
    return owner.equals(account);
  }

  public void checkOwner(Address caller) {
    if (! isOwner(caller)) {
      revert(UNAUTHORIZED);
    }
  }

  public void transferOwnership(Address caller, Address newOwner) {
    checkOwner(caller);
    requireNonZero(newOwner, INVALID_OWNER);
    transferOwnershipInternal(newOwner);
  }

  public void renounceOwnership(Address caller) {
    checkOwner(caller);
    transferOwnershipInternal(Address.ZERO);
  }

  protected void transferOwnershipInternal(Address newOwner) {
    owner = newOwner;
  }
}
