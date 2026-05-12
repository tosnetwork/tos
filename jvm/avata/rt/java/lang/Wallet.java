package java.lang;

// Single-owner Ed25519 wallet — the canonical wc=3 contract account.
//
// All entry methods are `public static` so that `@ContractEntry`
// admission accepts them.  Wallet extends Contract so subclasses can
// reuse `revert()` and the cell-backed storage handle.  Contract
// authors who want a fee-bearing / multi-sig / paymaster variant
// should subclass Wallet and add their own `@ContractEntry` methods
// alongside (or in place of) the ones below; v1 is intentionally
// minimal so the canonical genesis wallet image is small and easy
// to audit.
//
// Storage layout (all slots are keccak256("Wallet.<name>")):
//   OWNER_PUBKEY : 32 bytes — Ed25519 public key, stored verbatim.
//   NONCE        : Uint256  — monotonically increasing replay counter.
//   INIT_FLAG    : 1 byte   — 0x01 once init() has run.
//
// Verifier-profile compliance:
//   * No mutable static fields (only `static final` primitives/Strings).
//   * No <clinit> on the application class. Slot constants are computed
//     lazily inside helpers, not in a class initializer.
//   * @ContractEntry methods are `public static void` only.
//   * No synchronized / native methods, no finalize.
//   * No java.lang.invoke / lambdas — the verifier rejects invokedynamic.
public class Wallet extends Contract {

  // --------------------------------------------------------------------
  // Error signatures (ABI-style stable IDs surfaced through revert()).
  // --------------------------------------------------------------------
  public static final String ERR_ALREADY_INITIALIZED  = "Wallet_AlreadyInitialized()";
  public static final String ERR_NOT_INITIALIZED      = "Wallet_NotInitialized()";
  public static final String ERR_BAD_OWNER_KEY        = "Wallet_BadOwnerKey()";
  public static final String ERR_BAD_NONCE            = "Wallet_BadNonce(uint256,uint256)";
  public static final String ERR_BAD_SIGNATURE        = "Wallet_BadSignature()";
  public static final String ERR_BAD_PAYLOAD          = "Wallet_BadPayload()";

  // --------------------------------------------------------------------
  // Event topics (kept as static final String constants — verifier-safe;
  // the Bytes32 topic is derived on demand inside emit*()).
  // --------------------------------------------------------------------
  public static final String EVT_INITIALIZED = "WalletInitialized(bytes32)";
  public static final String EVT_EXECUTED    = "WalletExecuted(uint256,bytes32)";
  public static final String EVT_NONCE       = "WalletNonce(uint256)";

  // --------------------------------------------------------------------
  // Slot key derivation. `static final String` is verifier-admitted; the
  // Bytes32 slot itself is derived lazily because constant-folded
  // Bytes32 fields would create a <clinit>.  These names are
  // consensus-stable — genesis seeders compute keccak256 over exactly
  // these strings to populate the wallet's storage at block 0.
  // --------------------------------------------------------------------
  public static final String SLOT_OWNER_PUBKEY = "Wallet.ownerPubKey";
  public static final String SLOT_NONCE        = "Wallet.nonce";
  public static final String SLOT_INIT_FLAG    = "Wallet.initFlag";

  public static Bytes32 slot(String name) {
    return Crypto.keccak256(name.getBytes());
  }

  // --------------------------------------------------------------------
  // @ContractEntry surface
  // --------------------------------------------------------------------

  /** One-time owner-key install.  The host's first-activation gate
   *  (jvm/core/dispatch-engine.cpp) already requires the inbound src
   *  workchain to match wc=3 and the src.addr to match state.deployer,
   *  so init() doesn't need to re-check the caller here. */
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
   *  TOS Native (wc=0) wallets sign with Ed25519, so this matches the
   *  established TVM wallet signing semantics. Subclasses that want
   *  Ethereum-style secp256k1 + ecRecover can override `verify()`. */
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

    dispatch(payload);

    Event.emit(
        Event.topic(EVT_EXECUTED),
        Bytes32.wrap(digest),                     // topic1 = digest
        Bytes.wrap(nonce.toByteArray()));         // data   = nonce bytes
  }

  /** Read-only nonce view; useful for off-chain wallet UIs that need
   *  to build the next signed payload.  Emits an event because v1 has
   *  no synchronous response channel. */
  @ContractEntry
  public static void getNonce() {
    requireInitialized();
    Uint256 n = loadNonce(Storage.current());
    Event.emit(Event.topic(EVT_NONCE),
               Bytes.wrap(n.toByteArray()));
  }

  // --------------------------------------------------------------------
  // Internal helpers (protected so subclasses can override / reuse).
  // --------------------------------------------------------------------

  protected static Uint256 loadNonce(Storage s) {
    byte[] raw = s.load(slot(SLOT_NONCE));
    return raw == null ? Uint256.ZERO : Uint256.fromBytes(raw);
  }

  protected static void requireInitialized() {
    if (! Storage.current().contains(slot(SLOT_INIT_FLAG))) {
      revert(ERR_NOT_INITIALIZED);
    }
  }

  protected static Bytes32 digest(Uint256 nonce, Bytes payload) {
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

  /** Payload wire format (all big-endian, all sizes pinned for
   *  determinism):
   *
   *    payload := count:uint8 || transfer*
   *    transfer := destWorkchain:int32 || destAddr:bytes32 ||
   *                value:bytes32 || bodyLen:uint16 || body:bytes
   *
   *  count must be in [0, 12] to fit the per-tx outbound message cap
   *  the host enforces (kJvmMessageCountMax).  bodyLen is bounded by
   *  kJvmMessageBodyMaxBytes; the host re-checks the cap so contracts
   *  cannot exceed it by under-stating the length.
   *
   *  count=0 is valid — it produces a signed "no-op" entry useful for
   *  bumping the nonce without an outbound message (e.g. to invalidate
   *  a previously-signed payload).
   *
   *  Subclasses can override this method to swap in a different payload
   *  encoding (e.g. typed call data, batched operations with metadata,
   *  fee-aware forms). */
  protected static void dispatch(Bytes payload) {
    byte[] data = payload.rawBytes();
    if (data.length == 0) {
      revert(ERR_BAD_PAYLOAD);
    }
    int count = data[0] & 0xff;
    if (count > 12) {
      revert(ERR_BAD_PAYLOAD);
    }
    int offset = 1;
    for (int i = 0; i < count; ++i) {
      offset = dispatchOne(data, offset);
    }
    if (offset != data.length) {
      revert(ERR_BAD_PAYLOAD);
    }
  }

  /** Decode one transfer entry and emit the outbound message.  Returns
   *  the new offset into the payload buffer. */
  protected static int dispatchOne(byte[] data, int offset) {
    if (offset + 4 + 32 + 32 + 2 > data.length) {
      revert(ERR_BAD_PAYLOAD);
    }
    int wc = ((data[offset]     & 0xff) << 24)
           | ((data[offset + 1] & 0xff) << 16)
           | ((data[offset + 2] & 0xff) << 8)
           |  (data[offset + 3] & 0xff);
    offset += 4;

    byte[] destAddr = new byte[32];
    java.lang.System.arraycopy(data, offset, destAddr, 0, 32);
    offset += 32;

    byte[] valueBytes = new byte[32];
    java.lang.System.arraycopy(data, offset, valueBytes, 0, 32);
    offset += 32;

    int bodyLen = ((data[offset] & 0xff) << 8) | (data[offset + 1] & 0xff);
    offset += 2;
    if (offset + bodyLen > data.length) {
      revert(ERR_BAD_PAYLOAD);
    }
    byte[] body = new byte[bodyLen];
    if (bodyLen > 0) {
      java.lang.System.arraycopy(data, offset, body, 0, bodyLen);
    }
    offset += bodyLen;

    Address dest = new Address(wc, destAddr);
    Uint256 value = Uint256.fromBytes(valueBytes);
    java.lang.System.sendMessage(dest, value, body);
    return offset;
  }
}
