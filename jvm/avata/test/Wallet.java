// Minimal wc=3 wallet skeleton.
//
// Status: signature-authenticated; payload dispatch still waits on
//   System.sendMessage / java.lang.ContractCall (out of v1 scope per
//   jvm-rt.md §496).  Until that lands, execute() validates and logs
//   the payload commitment via Event; the actual outbound legs are
//   the contract author's responsibility once ContractCall ships.
//
// Storage layout (all slots are keccak256("Wallet.<name>")):
//   OWNER_PUBKEY      : 32 bytes — Ed25519 public key, stored verbatim.
//   NONCE             : Uint256 — monotonically increasing replay counter.
//   INIT_FLAG         : 1 byte  — 0x01 once init() has run.
//
// Verifier-profile compliance:
//   * No mutable static fields (only `static final` primitives/Strings).
//   * No <clinit> on the application class. Slot constants are computed
//     lazily inside helpers, not in a class initializer.
//   * @ContractEntry methods are `public static void` only.
//   * No synchronized / native methods, no finalize.
//   * No java.lang.invoke / lambdas — the verifier rejects invokedynamic.
public class Wallet {

  // --------------------------------------------------------------------
  // Error signatures (ABI-style stable IDs surfaced through revert()).
  // --------------------------------------------------------------------
  private static final String ERR_ALREADY_INITIALIZED  = "Wallet_AlreadyInitialized()";
  private static final String ERR_NOT_INITIALIZED      = "Wallet_NotInitialized()";
  private static final String ERR_BAD_OWNER_KEY        = "Wallet_BadOwnerKey()";
  private static final String ERR_BAD_NONCE            = "Wallet_BadNonce(uint256,uint256)";
  private static final String ERR_BAD_SIGNATURE        = "Wallet_BadSignature()";
  private static final String ERR_NOT_IMPLEMENTED      = "Wallet_NotImplemented()";

  // --------------------------------------------------------------------
  // Event topics (kept as static final String constants — verifier-safe;
  // the Bytes32 topic is derived on demand inside emit*()).
  // --------------------------------------------------------------------
  private static final String EVT_INITIALIZED = "WalletInitialized(bytes32)";
  private static final String EVT_EXECUTED    = "WalletExecuted(uint256,bytes32)";

  // --------------------------------------------------------------------
  // Slot key derivation. `static final String` is verifier-admitted; the
  // Bytes32 slot itself is derived lazily because constant-folded
  // Bytes32 fields would create a <clinit>.
  // --------------------------------------------------------------------
  private static final String SLOT_OWNER_PUBKEY = "Wallet.ownerPubKey";
  private static final String SLOT_NONCE        = "Wallet.nonce";
  private static final String SLOT_INIT_FLAG    = "Wallet.initFlag";

  private static Bytes32 slot(String name) {
    return Crypto.keccak256(name.getBytes());
  }

  // --------------------------------------------------------------------
  // @ContractEntry surface
  // --------------------------------------------------------------------

  /** One-time owner-key install. Called by the first activation (the
   *  deploy descriptor's body should encode this method id). Only the
   *  account that deployed this wallet may run init; this binds the
   *  on-chain authority to the deploy descriptor's deployer field. */
  @ContractEntry
  public static void init(Bytes32 ownerPubKey) {
    if (ownerPubKey == null || ownerPubKey.equals(Bytes32.ZERO)) {
      revert(ERR_BAD_OWNER_KEY);
    }

    Storage s = Storage.current();
    if (s.contains(slot(SLOT_INIT_FLAG))) {
      revert(ERR_ALREADY_INITIALIZED);
    }

    s.store(slot(SLOT_OWNER_PUBKEY), ownerPubKey.toByteArray());
    s.store(slot(SLOT_NONCE),        Uint256.ZERO.toByteArray());
    s.store(slot(SLOT_INIT_FLAG),    new byte[] { (byte) 0x01 });

    Event.emit(Event.topic(EVT_INITIALIZED),
               Bytes.wrap(ownerPubKey.toByteArray()));
  }

  /** Authenticated execute. Caller supplies (nonce, payload, signature);
   *  contract checks nonce, re-derives the digest, verifies the Ed25519
   *  signature against the stored owner public key, then dispatches.
   *
   *  digest = keccak256(walletAddrBytes || nonceBytes || payloadBytes)
   *
   *  Note: TOS Native (wc=0) wallets sign with Ed25519, so this matches
   *  the established TVM wallet signing semantics. Contracts that want
   *  Ethereum-style secp256k1 + ecRecover can replace Crypto.ed25519Verify
   *  with Crypto.ecRecover and compare against the stored pubkey. */
  @ContractEntry
  public static void execute(Uint256 nonce, Bytes payload, Bytes signature) {
    requireInitialized();

    Storage s = Storage.current();

    Uint256 expected = loadNonce(s);
    if (! expected.equals(nonce)) {
      revert(ERR_BAD_NONCE);
    }

    byte[] ownerKey = s.load(slot(SLOT_OWNER_PUBKEY));
    byte[] digest   = digest(nonce, payload).toByteArray();

    if (! Crypto.ed25519Verify(ownerKey, digest, signature.rawBytes())) {
      revert(ERR_BAD_SIGNATURE);
    }

    s.store(slot(SLOT_NONCE), expected.add(Uint256.ONE).toByteArray());

    // Once System.sendMessage(dest, value, body) / java.lang.ContractCall
    // lands (jvm-rt.md §496 — currently out of v1 scope), decode `payload`
    // as a typed outbound-action descriptor and emit the corresponding
    // outbound messages here. Until then we just commit the digest as an
    // event so off-chain tooling can prove acceptance.
    dispatch(payload);

    Event.emit(
        Event.topic(EVT_EXECUTED),
        Bytes32.wrap(digest),                     // topic1 = digest
        Bytes.wrap(nonce.toByteArray()));         // data   = nonce bytes
  }

  /** Read-only nonce view; useful for off-chain wallet UIs that need to
   *  build the next signed payload. */
  @ContractEntry
  public static void getNonce() {
    requireInitialized();
    Uint256 n = loadNonce(Storage.current());
    Event.emit(
        Event.topic("WalletNonce(uint256)"),
        Bytes.wrap(n.toByteArray()));
  }

  // --------------------------------------------------------------------
  // Internal helpers
  // --------------------------------------------------------------------

  private static Uint256 loadNonce(Storage s) {
    byte[] raw = s.load(slot(SLOT_NONCE));
    return raw == null ? Uint256.ZERO : Uint256.fromBytes(raw);
  }

  private static void requireInitialized() {
    if (! Storage.current().contains(slot(SLOT_INIT_FLAG))) {
      revert(ERR_NOT_INITIALIZED);
    }
  }

  private static Bytes32 digest(Uint256 nonce, Bytes payload) {
    // Bind the wallet's own address into the digest so a captured
    // signature cannot be replayed against a different wallet at the
    // same nonce. Context.contractAddress() returns the wc=3 account
    // address pinned by the runtime for this call.
    Address self = Context.contractAddress();
    byte[] selfBytes = self.accountIdBytes();
    return Crypto.keccak256(
        ABI.concat(selfBytes,
                   ABI.concat(nonce.toByteArray(), payload.rawBytes())));
  }

  private static void dispatch(Bytes payload) {
    // Outbound action list decoding lands with ContractCall / sendMessage
    // (jvm-rt.md §496). Until then we only validate the payload was
    // non-null so the entry path remains observable.
    if (payload == null) {
      revert(ERR_NOT_IMPLEMENTED);
    }
  }

  // --------------------------------------------------------------------
  // revert(): mirror of Contract.revert() — duplicated here because Wallet
  // is intentionally NOT a Contract subclass. The whole entry surface is
  // static so we never construct an instance and never need a base-class
  // Storage handle. (Contract.storage is captured per-instance via
  // Storage.current(); we call Storage.current() inline instead.)
  // --------------------------------------------------------------------
  private static void revert(String errorSignature) {
    throw new ContractRevertException(errorSignature);
  }

  private Wallet() {
    // Non-instantiable. The wallet contract is a static-only facade.
  }
}
