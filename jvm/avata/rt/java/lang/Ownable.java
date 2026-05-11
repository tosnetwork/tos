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

  /** Preferred entrypoint — pulls the caller from the per-call chain
   *  context installed by the workchain runtime. */
  public void checkOwner() {
    if (! Context.callerPresent() || ! isOwner(Context.caller())) {
      revert(UNAUTHORIZED);
    }
  }

  /** Legacy entrypoint preserved while the rt.jar gap plan migrates
   *  callers to the no-arg form. */
  @Deprecated
  public void checkOwner(Address caller) {
    if (! isOwner(caller)) {
      revert(UNAUTHORIZED);
    }
  }

  /** Preferred entrypoint — pulls the caller from Context. */
  public void transferOwnership(Address newOwner) {
    checkOwner();
    requireNonZero(newOwner, INVALID_OWNER);
    transferOwnershipInternal(newOwner);
  }

  @Deprecated
  public void transferOwnership(Address caller, Address newOwner) {
    checkOwner(caller);
    requireNonZero(newOwner, INVALID_OWNER);
    transferOwnershipInternal(newOwner);
  }

  /** Preferred entrypoint — pulls the caller from Context. */
  public void renounceOwnership() {
    checkOwner();
    transferOwnershipInternal(Address.ZERO);
  }

  @Deprecated
  public void renounceOwnership(Address caller) {
    checkOwner(caller);
    transferOwnershipInternal(Address.ZERO);
  }

  protected void transferOwnershipInternal(Address newOwner) {
    owner = newOwner;
  }
}
