package java.lang;

public class Ownable2Step extends Ownable {
  private Address pendingOwner;

  public Ownable2Step(Address initialOwner) {
    super(initialOwner);
    pendingOwner = Address.ZERO;
  }

  public final Address pendingOwner() {
    return pendingOwner;
  }

  public final boolean hasPendingOwner() {
    return ! pendingOwner.isZero();
  }

  public void transferOwnership(Address caller, Address newOwner) {
    checkOwner(caller);
    requireNonZero(newOwner, INVALID_OWNER);
    pendingOwner = newOwner;
  }

  public void acceptOwnership(Address caller) {
    if (! pendingOwner.equals(caller)) {
      revert(UNAUTHORIZED);
    }
    pendingOwner = Address.ZERO;
    transferOwnershipInternal(caller);
  }
}
