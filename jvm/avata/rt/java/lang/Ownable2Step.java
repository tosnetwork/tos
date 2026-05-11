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

  /** Preferred entrypoint — pulls the caller from the per-call chain
   *  context installed by the workchain runtime. */
  @Override
  public void transferOwnership(Address newOwner) {
    transferOwnership(Context.caller(), newOwner);
  }

  @Deprecated
  @Override
  public void transferOwnership(Address caller, Address newOwner) {
    checkOwner(caller);
    requireNonZero(newOwner, INVALID_OWNER);
    pendingOwner = newOwner;
  }

  /** Preferred entrypoint — pulls the caller from Context. */
  public void acceptOwnership() {
    acceptOwnership(Context.caller());
  }

  @Deprecated
  public void acceptOwnership(Address caller) {
    if (! pendingOwner.equals(caller)) {
      revert(UNAUTHORIZED);
    }
    pendingOwner = Address.ZERO;
    transferOwnershipInternal(caller);
  }
}
