"""
Contract deployer for TOS JSON-RPC test suite.

Deploys wallet, Jetton, NFT, and DNS contracts on a live TOS testnet using
the pre-funded main wallet at -1:000...000.  All deployment happens via Fift
scripts + the JSON-RPC ``sendBoc`` endpoint — no lite-client needed.
"""
import base64
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

import requests

# ── Paths ────────────────────────────────────────────────────────────────
TOS_ROOT = Path(__file__).resolve().parents[2]  # ~/tos
FIFT_EXE = TOS_ROOT / "build" / "crypto" / "fift"
FUNC_EXE = TOS_ROOT / "build" / "crypto" / "func"
FIFT_INCLUDES = f"{TOS_ROOT / 'crypto/fift/lib'}:{TOS_ROOT / 'crypto/smartcont'}"

MAIN_WALLET_PK = Path("/tmp/main-wallet.pk")
MAIN_WALLET_ADDR = "-1:0000000000000000000000000000000000000000000000000000000000000000"


# ── Low-level helpers ────────────────────────────────────────────────────

def run_fift(script: str, working_dir: Optional[Path] = None) -> str:
    """Execute a Fift script, return stdout."""
    cleanup = working_dir is None
    if working_dir is None:
        working_dir = Path(tempfile.mkdtemp(prefix="tos_deploy_"))
    script_path = working_dir / "script.fif"
    script_path.write_text(script)
    result = subprocess.run(
        [str(FIFT_EXE), "-I", FIFT_INCLUDES, "-s", "script.fif"],
        cwd=str(working_dir),
        capture_output=True,
        text=True,
    )
    if cleanup:
        for f in working_dir.iterdir():
            f.unlink()
        working_dir.rmdir()
    if result.returncode != 0:
        raise RuntimeError(f"Fift failed:\n{result.stderr}\n{result.stdout}")
    return result.stdout


def get_seqno(endpoint: str, address: str) -> int:
    """Get a wallet's seqno via runGetMethod."""
    resp = requests.post(
        f"{endpoint}runGetMethod",
        json={"address": address, "method": "seqno", "stack": []},
    )
    data = resp.json()
    if data.get("ok") and data["result"]["exit_code"] == 0:
        stack = data["result"]["stack"]
        if stack:
            return int(stack[0][1])
    return 0


def send_boc(endpoint: str, boc_b64: str) -> dict:
    """Send a BOC via the sendBoc JSON-RPC method."""
    resp = requests.post(f"{endpoint}sendBoc", json={"boc": boc_b64})
    return resp.json()


def wait_active(endpoint: str, address: str, timeout: int = 30) -> bool:
    """Poll getAddressState until the account is active (or timeout)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        resp = requests.get(f"{endpoint}getAddressState", params={"address": address})
        data = resp.json()
        if data.get("ok") and data.get("result") == "active":
            return True
        time.sleep(0.5)
    return False


def _read_cache() -> dict:
    if not CACHE_FILE.exists():
        return {}
    return json.loads(CACHE_FILE.read_text())


def _is_success_entry(entry: object) -> bool:
    return isinstance(entry, dict) and bool(entry.get("address"))


def _merge_category_results(previous: dict, current: dict) -> dict:
    merged = {}
    for key in set(previous.keys()) | set(current.keys()):
        cur = current.get(key)
        prev = previous.get(key)
        if _is_success_entry(cur):
            merged[key] = cur
        elif cur is None and prev is not None:
            merged[key] = prev
        elif not _is_success_entry(cur) and _is_success_entry(prev):
            # Preserve last known-good address instead of overwriting it with None/error.
            # Attach the latest deployment error for visibility.
            merged[key] = dict(prev)
            if isinstance(cur, dict) and cur.get("error"):
                merged[key]["last_deploy_error"] = cur["error"]
        else:
            merged[key] = cur if cur is not None else prev
    return merged


def _write_cache_atomic(data: dict) -> None:
    tmp_path = CACHE_FILE.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(data, indent=2))
    tmp_path.replace(CACHE_FILE)


# ── Main wallet transfer ─────────────────────────────────────────────────

_TRANSFER_TEMPLATE = """\
"TosUtil.fif" include
"Asm.fif" include

// Load main wallet private key
"{pk_path}" load-keypair constant mw_pk constant mw_pub

// Parameters
{seqno} constant mw_seqno
{dest_wc} constant dest_wc
x{{{dest_addr_hex}}} 256 B>u@ constant dest_addr
{amount_nano} constant amount
{bounce} constant bounce_flag

// Build internal message
<b b{{0}} s,                      // int_msg_info tag (0)
   bounce_flag 1 i,              // ihr_disabled=true
   bounce_flag 1 i,              // bounce
   b{{0}} s,                      // bounced=false
   b{{00}} s,                     // src: addr_none
   // dest: addr_std
   b{{10}} s, b{{0}} s, dest_wc 8 i, dest_addr 256 u,
   amount Tmi*>GR Tomi, 0 9 u,   // ihr_fee
   0 Tomi,                        // fwd_fee (set by validators)
   0 64 u,                        // created_lt
   0 32 u,                        // created_at
{state_init_block}
   b{{0}} s,                      // body: empty (or could carry init)
b>
constant int_msg

// Build main-wallet external message payload: seqno(32) + mode(8) + msg_ref
<b mw_seqno 32 u, 3 8 u, int_msg ref, b>
dup constant payload
dup hashu mw_pk ed25519_sign_uint constant signature

// External message to main wallet
<b b{{1000100}} s,
   Masterchain {main_wc_addr} 2dup addr,
   0 Tomi, b{{00}} s,            // no StateInit on the external
   b{{1}} s,
   <b signature B, payload <s s, b> ref,
b>
2 boc+>B
// Output as base64
dup Blen 0
{{ over 1 B@ 8 u@
   dup 26 < {{ 65 + }} {{
   dup 52 < {{ 71 + }} {{
   dup 62 < {{ 4- 48 + }} {{
   62 = {{ 43 }} {{ 47 }} cond
   }} cond }} cond }} cond
   (char) emit 1+
}} over Blen * times drop drop
"" print cr

// Output new wallet address
."ADDR:" dest_wc . .":" dest_addr 256 u>B Bx. cr
"""

# Simpler approach: output BOC as hex, convert in Python
_TRANSFER_TEMPLATE_V2 = """\
"TosUtil.fif" include
"Asm.fif" include

// Load main wallet private key
"{pk_path}" load-keypair constant mw_pk constant mw_pub

// Parameters
{seqno} constant mw_seqno
{dest_wc} constant dest_wc
0x{dest_addr_hex} constant dest_addr
{amount_nano} constant amount

// Build internal message body
<b
  b{{0}} s,                  // int_msg_info tag
  b{{1}} s,                  // ihr_disabled
  {bounce_bit} s,            // bounce
  b{{0}} s,                  // bounced
  b{{00}} s,                 // src: addr_none
  b{{10}} s, b{{0}} s,       // dest: addr_std, anycast=none
  dest_wc 8 i,
  dest_addr 256 u,
  amount Tomi,               // value
  b{{0}} s,                  // extra currencies: none
  0 Tomi,                    // ihr_fee
  0 Tomi,                    // fwd_fee
  0 64 u,                    // created_lt
  0 32 u,                    // created_at
  {state_init_code}
  b{{0}} s,                  // body: inline, empty
b> constant int_msg

// Payload: seqno(32) + mode(8) + internal_msg_ref
<b mw_seqno 32 u, 3 8 u, int_msg ref, b>
dup constant payload
dup hashu mw_pk ed25519_sign_uint constant signature

// External message to main wallet (-1:000...000)
<b b{{1000100}} s,
   -1 0 addr,
   0 Tomi, b{{00}} s,
   signature B, payload <s s,
b>
2 boc+>B dup ."BOC:" Bx. cr
"""


def _transfer_from_main_wallet(
    endpoint: str,
    dest_wc: int,
    dest_addr_hex: str,
    amount_nano: int,
    state_init_fift: str = "",
    bounce: bool = True,
) -> bool:
    """Send an internal message from the main wallet to dest, optionally with StateInit."""
    seqno = get_seqno(endpoint, MAIN_WALLET_ADDR)

    if state_init_fift:
        si_code = f"b{{1}} s, b{{1}} s, {state_init_fift} ref, b{{0}} s,  // StateInit present"
    else:
        si_code = "b{0} s,  // no StateInit"

    bounce_bit = 'b{1}' if bounce else 'b{0}'

    script = _TRANSFER_TEMPLATE_V2.format(
        pk_path=str(MAIN_WALLET_PK),
        seqno=seqno,
        dest_wc=dest_wc,
        dest_addr_hex=dest_addr_hex,
        amount_nano=amount_nano,
        state_init_code=si_code,
        bounce_bit=bounce_bit,
    )

    output = run_fift(script)

    # Parse BOC hex from output
    boc_hex = None
    for line in output.strip().split("\n"):
        if line.startswith("BOC:"):
            boc_hex = line[4:].strip()
            break

    if not boc_hex:
        raise RuntimeError(f"No BOC in Fift output:\n{output}")

    boc_bytes = bytes.fromhex(boc_hex)
    boc_b64 = base64.b64encode(boc_bytes).decode()

    result = send_boc(endpoint, boc_b64)
    return result.get("ok", False)


# ── Wallet deployment ────────────────────────────────────────────────────

# Fift script to compute wallet address + StateInit for a given code include
_WALLET_INIT_TEMPLATE = """\
"TosUtil.fif" include
"Asm.fif" include

// Include compiled wallet code
{code_include}
constant wallet_code

// Generate keypair
"{key_file}" load-generate-keypair
constant wallet_pk
constant wallet_pub

// Build data cell
<b 0 32 u, {data_extra} wallet_pub B, b> constant wallet_data

// Build StateInit
<b b{{0011}} s, wallet_code ref, wallet_data ref, null dict, b>
dup constant state_init

// Compute address (hashu returns a 256-bit integer)
hashu constant addr_hash
."ADDR:{dest_wc}:" addr_hash 256 u>B Bx. cr

// Serialize StateInit as BOC hex
state_init 2 boc+>B ."SI_BOC:" Bx. cr

// Output code hash for verification
wallet_code hashu 256 u>B ."CODE_HASH:" Bx. cr
"""


def deploy_wallet_contract(
    endpoint: str,
    code_include: str,
    data_extra: str = "",
    dest_wc: int = 0,
    amount_nano: int = 1_000_000_000,  # 1 TOS
    key_name: str = "test-wallet",
) -> dict:
    """
    Deploy a wallet contract.

    Returns {"address": "wc:hex", "code_hash": "hex"}.
    """
    working_dir = Path(tempfile.mkdtemp(prefix="tos_wallet_"))

    # Copy main wallet key for Fift access
    import shutil
    shutil.copy(str(MAIN_WALLET_PK), str(working_dir / "main-wallet.pk"))

    script = _WALLET_INIT_TEMPLATE.format(
        code_include=code_include,
        key_file=key_name,
        data_extra=data_extra,
        dest_wc=dest_wc,
    )

    output = run_fift(script, working_dir)

    # Parse address and StateInit BOC
    address = None
    si_boc_hex = None
    code_hash = None

    for line in output.strip().split("\n"):
        if line.startswith("ADDR:"):
            address = line[5:].strip()
        elif line.startswith("SI_BOC:"):
            si_boc_hex = line[7:].strip()
        elif line.startswith("CODE_HASH:"):
            code_hash = line[10:].strip().lower()

    if not address or not si_boc_hex:
        raise RuntimeError(f"Failed to parse wallet init output:\n{output}")

    # Parse address components
    parts = address.split(":")
    addr_wc = int(parts[0])
    addr_hex = parts[1].lower()

    # Build StateInit cell reference in Fift notation
    # We need to pass it as a cell reference to the transfer script
    # Simplest: write the StateInit BOC to a file and load it in Fift
    si_boc_path = working_dir / "state_init.boc"
    si_boc_path.write_bytes(bytes.fromhex(si_boc_hex))

    # Transfer from main wallet with StateInit
    seqno = get_seqno(endpoint, MAIN_WALLET_ADDR)

    transfer_script = f"""\
"TosUtil.fif" include
"Asm.fif" include

// Load main wallet private key
"main-wallet.pk" load-keypair constant mw_pk constant mw_pub

// Load StateInit from file
"state_init.boc" file>B B>boc constant si_cell

// Build internal message with StateInit
<b
  b{{0}} s,                  // int_msg_info tag
  b{{1}} s,                  // ihr_disabled
  b{{0}} s,                  // bounce=false (init message)
  b{{0}} s,                  // bounced
  b{{00}} s,                 // src: addr_none
  b{{10}} s, b{{0}} s,       // dest: addr_std
  {addr_wc} 8 i,
  0x{addr_hex} 256 u,
  {amount_nano} Tomi,        // value
  b{{0}} s,                  // no extra currencies
  0 Tomi,                    // ihr_fee
  0 Tomi,                    // fwd_fee
  0 64 u, 0 32 u,           // created_lt, created_at
  b{{1}} s,                  // StateInit present (as ref? as inline?)
  b{{1}} s,                  // StateInit is a ref
  si_cell ref,
  b{{0}} s,                  // body: empty (either bit or ref)
  b{{0}} s,                  // body: empty
b> constant int_msg

// Payload: seqno(32) + mode(8) + internal_msg_ref
<b {seqno} 32 u, 3 8 u, int_msg ref, b>
dup constant payload
dup hashu mw_pk ed25519_sign_uint constant signature

// External message to main wallet (-1:000...000)
// Format: header + addr + import_fee + no_init + signature + payload_inline
<b b{{1000100}} s,
   -1 0 addr,
   0 Tomi, b{{00}} s,
   signature B, payload <s s,
b>
2 boc+>B dup ."BOC:" Bx. cr
"""

    output2 = run_fift(transfer_script, working_dir)

    boc_hex = None
    for line in output2.strip().split("\n"):
        if line.startswith("BOC:"):
            boc_hex = line[4:].strip()
            break

    if not boc_hex:
        raise RuntimeError(f"No BOC in transfer output:\n{output2}")

    boc_bytes = bytes.fromhex(boc_hex)
    boc_b64 = base64.b64encode(boc_bytes).decode()

    result = send_boc(endpoint, boc_b64)
    if not result.get("ok"):
        raise RuntimeError(f"sendBoc failed: {result}")

    full_addr = f"{addr_wc}:{addr_hex}"

    # Wait for contract to become active
    if not wait_active(endpoint, full_addr, timeout=30):
        raise RuntimeError(f"Wallet {full_addr} did not become active within 30s")

    # Cleanup
    for f in working_dir.iterdir():
        f.unlink()
    working_dir.rmdir()

    return {"address": full_addr, "code_hash": code_hash}


# ── Wallet type configs ──────────────────────────────────────────────────

WALLET_CONFIGS = {
    "wallet_v1": {
        "code_include": '"auto/simple-wallet-code.fif" include',
        "data_extra": "",  # seqno(32) + pubkey(256)
    },
    "wallet_v3r2": {
        "code_include": '"auto/wallet3-code.fif" include',
        "data_extra": "0 32 u,",  # seqno(32) + subwallet_id(32) + pubkey(256)
    },
    "wallet_v4r2": {
        "code_include": '"auto/wallet-v4-code.fif" include',
        "data_extra": "0 32 u,",  # seqno(32) + subwallet_id(32) + pubkey(256) + plugins(dict=null appended)
    },
    "wallet_v5r1": {
        "code_include": '"auto/wallet-v5-code.fif" include',
        "data_extra": "0 1 u, 0 32 u, 0 32 u,",  # is_signature_allowed(1) + seqno(32) + subwallet_id(32) + pubkey(256)
    },
    "highload_v1": {
        "code_include": '"auto/highload-wallet-code.fif" include',
        "data_extra": "0 32 u,",  # seqno(32) + subwallet_id(32) + pubkey(256)
    },
    "highload_v2": {
        "code_include": '"auto/highload-wallet-v2-code.fif" include',
        "data_extra": "0 32 u,",  # subwallet_id(32) + last_cleaned(64=0) + pubkey(256)
    },
}


def deploy_all_wallets(endpoint: str) -> dict:
    """Deploy all wallet types, return {type: {"address": ..., "code_hash": ...}}."""
    results = {}
    for name, cfg in WALLET_CONFIGS.items():
        print(f"Deploying {name}...")
        try:
            info = deploy_wallet_contract(
                endpoint,
                code_include=cfg["code_include"],
                data_extra=cfg["data_extra"],
                dest_wc=0,
                key_name=name,
            )
            results[name] = info
            print(f"  -> {info['address']}  (code_hash={info['code_hash'][:16]}...)")
        except Exception as e:
            print(f"  FAILED: {e}")
            results[name] = {"address": None, "code_hash": None, "error": str(e)}

    print("Deploying multisig...")
    try:
        info = deploy_multisig_contract(endpoint, dest_wc=0)
        results["multisig"] = info
        print(f"  -> {info['address']}  (code_hash={info['code_hash'][:16]}...)")
    except Exception as e:
        print(f"  FAILED: {e}")
        results["multisig"] = {"address": None, "code_hash": None, "error": str(e)}

    print("Deploying restricted wallet...")
    try:
        info = deploy_restricted_wallet(endpoint, dest_wc=0)
        results["restricted"] = info
        print(f"  -> {info['address']}  (code_hash={info['code_hash'][:16]}...)")
    except Exception as e:
        print(f"  FAILED: {e}")
        results["restricted"] = {"address": None, "code_hash": None, "error": str(e)}

    print("Deploying restricted wallet (expired)...")
    try:
        info = deploy_restricted_wallet_expired(endpoint, dest_wc=0)
        results["restricted_expired"] = info
        print(f"  -> {info['address']}  (code_hash={info['code_hash'][:16]}...)")
    except Exception as e:
        print(f"  FAILED: {e}")
        results["restricted_expired"] = {"address": None, "code_hash": None, "error": str(e)}

    print("Deploying nominator pool...")
    try:
        info = deploy_nominator_pool(endpoint, dest_wc=0)
        results["nominator_pool"] = info
        print(f"  -> {info['address']}  (code_hash={info['code_hash'][:16]}...)")
    except Exception as e:
        print(f"  FAILED: {e}")
        results["nominator_pool"] = {"address": None, "code_hash": None, "error": str(e)}

    print("Deploying nominator pool (with withdraw request)...")
    try:
        info = deploy_nominator_pool_with_withdraw(endpoint, dest_wc=0)
        results["nominator_pool_withdraw"] = info
        print(f"  -> {info['address']}  (code_hash={info['code_hash'][:16]}...)")
    except Exception as e:
        print(f"  FAILED: {e}")
        results["nominator_pool_withdraw"] = {"address": None, "code_hash": None, "error": str(e)}

    print("Deploying session wallet...")
    try:
        info = deploy_session_wallet(endpoint, dest_wc=0)
        results["session_wallet"] = info
        print(f"  -> {info['address']}  (code_hash={info['code_hash'][:16]}...)")
    except Exception as e:
        print(f"  FAILED: {e}")
        results["session_wallet"] = {"address": None, "code_hash": None, "error": str(e)}
    return results


# ── Generic contract deployment (code + data as Fift) ────────────────────

_GENERIC_DEPLOY_TEMPLATE = """\
"TosUtil.fif" include
"Asm.fif" include

// Build code cell
{code_fift}
constant contract_code

// Build data cell
{data_fift}
constant contract_data

// Build StateInit
<b b{{0011}} s, contract_code ref, contract_data ref, null dict, b>
dup constant state_init
hashu constant addr_hash
."ADDR:{dest_wc}:" addr_hash 256 u>B Bx. cr
state_init 2 boc+>B ."SI_BOC:" Bx. cr
contract_code hashu 256 u>B ."CODE_HASH:" Bx. cr
"""


def deploy_generic_contract(
    endpoint: str,
    code_fift: str,
    data_fift: str,
    dest_wc: int = 0,
    amount_nano: int = 500_000_000,  # 0.5 TOS
) -> dict:
    """Deploy an arbitrary contract given code and data as Fift expressions."""
    working_dir = Path(tempfile.mkdtemp(prefix="tos_contract_"))
    shutil.copy(str(MAIN_WALLET_PK), str(working_dir / "main-wallet.pk"))

    # Copy compiled BOC files for code references
    for boc in ["/tmp/jetton-minter-code.boc", "/tmp/jetton-wallet-code.boc",
                "/tmp/nft-collection-code.boc", "/tmp/nft-item-code.boc",
                "/tmp/pool-code.boc"]:
        if os.path.exists(boc):
            shutil.copy(boc, str(working_dir / os.path.basename(boc)))

    script = _GENERIC_DEPLOY_TEMPLATE.format(
        code_fift=code_fift,
        data_fift=data_fift,
        dest_wc=dest_wc,
    )
    output = run_fift(script, working_dir)

    address = si_boc_hex = code_hash = None
    for line in output.strip().split("\n"):
        if line.startswith("ADDR:"): address = line[5:].strip()
        elif line.startswith("SI_BOC:"): si_boc_hex = line[7:].strip()
        elif line.startswith("CODE_HASH:"): code_hash = line[10:].strip().lower()

    if not address or not si_boc_hex:
        raise RuntimeError(f"Failed to parse contract init:\n{output}")

    parts = address.split(":")
    addr_wc = int(parts[0])
    addr_hex = parts[1].lower()

    # Write StateInit for transfer
    (working_dir / "state_init.boc").write_bytes(bytes.fromhex(si_boc_hex))

    seqno = get_seqno(endpoint, MAIN_WALLET_ADDR)

    transfer_script = f"""\
"TosUtil.fif" include
"Asm.fif" include
"main-wallet.pk" load-keypair constant mw_pk constant mw_pub
"state_init.boc" file>B B>boc constant si_cell

<b
  b{{0}} s, b{{1}} s, b{{0}} s, b{{0}} s, b{{00}} s,
  b{{10}} s, b{{0}} s, {addr_wc} 8 i,
  0x{addr_hex} 256 u,
  {amount_nano} Tomi, b{{0}} s, 0 Tomi, 0 Tomi, 0 64 u, 0 32 u,
  b{{1}} s, b{{1}} s, si_cell ref, b{{0}} s, b{{0}} s,
b> constant int_msg

<b {seqno} 32 u, 3 8 u, int_msg ref, b>
dup constant payload
dup hashu mw_pk ed25519_sign_uint constant signature

<b b{{1000100}} s,
   -1 0 addr,
   0 Tomi, b{{00}} s,
   signature B, payload <s s,
b>
2 boc+>B dup ."BOC:" Bx. cr
"""
    output2 = run_fift(transfer_script, working_dir)

    boc_hex = None
    for line in output2.strip().split("\n"):
        if line.startswith("BOC:"): boc_hex = line[4:].strip()
    if not boc_hex:
        raise RuntimeError(f"No BOC in transfer:\n{output2}")

    boc_b64 = base64.b64encode(bytes.fromhex(boc_hex)).decode()
    result = send_boc(endpoint, boc_b64)
    if not result.get("ok"):
        raise RuntimeError(f"sendBoc failed: {result}")

    full_addr = f"{addr_wc}:{addr_hex}"
    if not wait_active(endpoint, full_addr, timeout=30):
        raise RuntimeError(f"Contract {full_addr} did not become active within 30s")

    # Cleanup
    shutil.rmtree(str(working_dir))
    return {"address": full_addr, "code_hash": code_hash}


def deploy_multisig_contract(
    endpoint: str,
    dest_wc: int = 0,
    amount_nano: int = 1_000_000_000,
    wallet_id: int = 0x4D534947,
    n: int = 3,
    k: int = 2,
) -> dict:
    """Deploy a minimal multisig contract with generated owner keys."""
    if n <= 0 or k <= 0 or k > n:
        raise ValueError("invalid multisig parameters")

    owners_init = []
    for idx in range(n):
        key_name = f"multisig-owner-{idx}"
        owners_init.append(
            f'"{key_name}" load-generate-keypair constant owner{idx}_pk constant owner{idx}_pub'
        )

    owner_dict_build = ["dictnew"]
    for idx in range(n):
        owner_dict_build.append(f"{idx} owner{idx}_pub 256 B>u@ add-owner")

    data_fift = """\
{{ <b swap 256 u, 0 8 u, b> <s swap rot 8 udict! not abort"cannot add owner" }} : add-owner
{owners_init}
{owner_dict_build}
<b
  {wallet_id} 32 u,
  {n} 8 u,
  {k} 8 u,
  0 64 u,
  swap dict,
  null dict,
b>""".format(
        owners_init="\n".join(owners_init),
        owner_dict_build="\n".join(owner_dict_build),
        wallet_id=wallet_id,
        n=n,
        k=k,
    )

    info = deploy_generic_contract(
        endpoint,
        code_fift='"auto/multisig-code.fif" include',
        data_fift=data_fift,
        dest_wc=dest_wc,
        amount_nano=amount_nano,
    )

    info["n"] = n
    info["k"] = k
    return info


def deploy_restricted_wallet(
    endpoint: str,
    dest_wc: int = 0,
    amount_nano: int = 1_000_000_000,
    start_at: int = 0,
    reserve_amount: int = 500_000_000,  # 0.5 TOS in nanotomi
) -> dict:
    """
    Deploy a restricted wallet v3 in already-initialized state.

    Builds the data cell with seqno=1 (post-init), a generated public key,
    start_at, and a single-entry vesting dict reserving *reserve_amount*.

    Returns {"address": ..., "code_hash": ..., "start_at": ..., "reserve_amount": ...}.
    """
    # Build data cell via Fift.
    # After initialization the restricted-wallet3 data layout is:
    #   seqno(32) + subwallet_id(32) + public_key(256) + start_at(32) + rdict
    # The vesting dict maps int32 elapsed-seconds -> Tomi-encoded reserve.
    data_fift = f"""\
"restricted-test" load-generate-keypair constant rw_pk constant rw_pub
{{ <b rot Tomi, swap rot 32 b>idict! not abort"cannot add value" }} : rdict-entry
dictnew
{reserve_amount} 0 rdict-entry
constant rdict
<b
  1 32 u,
  0 32 u,
  rw_pub 256 B>u@ 256 u,
  {start_at} 32 u,
  rdict dict,
b>"""

    info = deploy_generic_contract(
        endpoint,
        code_fift='"auto/restricted-wallet3-code.fif" include',
        data_fift=data_fift,
        dest_wc=dest_wc,
        amount_nano=amount_nano,
    )

    info["start_at"] = start_at
    info["reserve_amount"] = reserve_amount
    return info


def deploy_restricted_wallet_expired(
    endpoint: str,
    dest_wc: int = 0,
    amount_nano: int = 1_000_000_000,
    start_at: int = 0,
) -> dict:
    """
    Deploy a restricted wallet v3 with fully-elapsed vesting (reserve == 0).

    The single vesting dict entry has time offset 0 and reserve amount 0,
    meaning the restriction is fully released from the start. The delegation
    status should materialize as "expired".

    Returns {"address": ..., "code_hash": ..., "start_at": ..., "reserve_amount": 0}.
    """
    data_fift = f"""\
"restricted-expired" load-generate-keypair constant rw_pk constant rw_pub
{{ <b rot Tomi, swap rot 32 b>idict! not abort"cannot add value" }} : rdict-entry
dictnew
0 0 rdict-entry
constant rdict
<b
  1 32 u,
  0 32 u,
  rw_pub 256 B>u@ 256 u,
  {start_at} 32 u,
  rdict dict,
b>"""

    info = deploy_generic_contract(
        endpoint,
        code_fift='"auto/restricted-wallet3-code.fif" include',
        data_fift=data_fift,
        dest_wc=dest_wc,
        amount_nano=amount_nano,
    )

    info["start_at"] = start_at
    info["reserve_amount"] = 0
    return info


# ── Nominator pool deployment ───────────────────────────────────────────

POOL_SRC = TOS_ROOT / "crypto/smartcont/nominator-pool"
_POOL_FIF = Path("/tmp/pool.fif")
_POOL_BOC = Path("/tmp/pool-code.boc")


def _ensure_pool_compiled() -> None:
    """Compile the nominator pool FunC source into a Fift include and then a BOC."""
    if not _POOL_FIF.exists():
        result = subprocess.run(
            [str(FUNC_EXE), "-SPA", "-o", str(_POOL_FIF), "pool.fc"],
            cwd=str(POOL_SRC),
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"func compile failed: {result.stderr}")

    if not _POOL_BOC.exists():
        fift_script = """\
"TosUtil.fif" include
"Asm.fif" include
"%s" include
2 boc+>B "%s" B>file
""" % (str(_POOL_FIF), str(_POOL_BOC))
        run_fift(fift_script)


def deploy_nominator_pool(
    endpoint: str,
    dest_wc: int = 0,
    amount_nano: int = 2_000_000_000,
    validator_reward_share: int = 4000,   # 40%
    max_nominators: int = 40,
    min_validator_stake: int = 1_000_000_000,
    min_nominator_stake: int = 100_000_000,
) -> dict:
    """
    Deploy a nominator pool with one pre-seeded nominator in the dictionary.

    The pre-seeded nominator uses a deterministic address so the delegation
    inspection test can verify list output even without sending a real deposit.

    Returns {"address": ..., "code_hash": ..., "nominators_count": 1,
             "validator_reward_share": ..., "max_nominators": ...,
             "min_validator_stake": ..., "min_nominator_stake": ...}.
    """
    _ensure_pool_compiled()

    # Build data cell.
    # Storage layout (from pool.fc save_data):
    #   state(8) + nominators_count(16) + stake_amount_sent(Grams) +
    #   validator_amount(Grams) + config(ref) + nominators(dict) +
    #   withdraw_requests(dict) + stake_at(32) + saved_validator_set_hash(256) +
    #   validator_set_changes_count(8) + validator_set_change_time(32) +
    #   stake_held_for(32) + config_proposal_votings(dict)
    #
    # Config cell:
    #   validator_address(256) + validator_reward_share(16) +
    #   max_nominators_count(16) + min_validator_stake(Grams) +
    #   min_nominator_stake(Grams)
    #
    # Nominator dict: udict keyed by 256-bit address, value = coins(amount) +
    #   coins(pending_deposit_amount).

    # Pre-seed one nominator so delegation inspection has data to return.
    # Use a deterministic address (0xABCD...0001) with 1 TOS staked.
    nominator_addr_hex = "ABCD" + "0" * 59 + "1"
    nominator_amount = 1_000_000_000  # 1 TOS in nanotomi

    data_fift = f"""\
// Build nominators dict with one pre-seeded entry
dictnew
<b {nominator_amount} Tomi, 0 Tomi, b> <s
0x{nominator_addr_hex} rot 256 udict! not abort"cannot seed nominator"
constant nominators_dict

<b
  0 8 u,                             // state = 0 (idle/accepting deposits)
  1 16 u,                            // nominators_count = 1
  0 Tomi,                            // stake_amount_sent = 0
  0 Tomi,                            // validator_amount = 0
  <b                                  // config cell
    0 256 u,                          // validator_address (zero hash = fake)
    {validator_reward_share} 16 u,
    {max_nominators} 16 u,
    {min_validator_stake} Tomi,
    {min_nominator_stake} Tomi,
  b> ref,
  nominators_dict dict,              // nominators (pre-seeded)
  null dict,                         // withdraw_requests (empty)
  0 32 u,                            // stake_at = 0
  0 256 u,                           // saved_validator_set_hash = 0
  0 8 u,                             // validator_set_changes_count = 0
  0 32 u,                            // validator_set_change_time = 0
  0 32 u,                            // stake_held_for = 0
  null dict,                         // config_proposal_votings (empty)
b>"""

    code_fift = f'"{_POOL_BOC}" file>B B>boc'

    info = deploy_generic_contract(
        endpoint,
        code_fift=code_fift,
        data_fift=data_fift,
        dest_wc=dest_wc,
        amount_nano=amount_nano,
    )

    info["nominators_count"] = 1
    info["validator_reward_share"] = validator_reward_share
    info["max_nominators"] = max_nominators
    info["min_validator_stake"] = min_validator_stake
    info["min_nominator_stake"] = min_nominator_stake
    return info


def deploy_nominator_pool_with_withdraw(
    endpoint: str,
    dest_wc: int = 0,
    amount_nano: int = 2_000_000_000,
) -> dict:
    """
    Deploy a nominator pool with one nominator AND a withdraw request for that
    nominator.  This creates the on-chain state that causes list_nominators()
    to return withdraw_requested = -1 (true) for the pre-seeded address.

    The withdraw_requests dict uses the same 256-bit address key as the
    nominators dict.  The value is an empty cell (begin_cell() in FunC).
    """
    _ensure_pool_compiled()

    nominator_addr_hex = "ABCD" + "0" * 59 + "2"  # different from the non-withdraw pool
    nominator_amount = 1_000_000_000  # 1 TOS

    data_fift = f"""\
// Build nominators dict with one pre-seeded entry
dictnew
<b {nominator_amount} Tomi, 0 Tomi, b> <s
0x{nominator_addr_hex} rot 256 udict! not abort"cannot seed nominator"
constant nominators_dict

// Build withdraw_requests dict with the SAME address (marks withdraw requested)
dictnew
<b b> <s
0x{nominator_addr_hex} rot 256 udict! not abort"cannot seed withdraw request"
constant withdraw_dict

<b
  0 8 u,                             // state = 0 (idle)
  1 16 u,                            // nominators_count = 1
  0 Tomi,                            // stake_amount_sent = 0
  0 Tomi,                            // validator_amount = 0
  <b
    0 256 u,                          // validator_address (fake)
    4000 16 u,
    40 16 u,
    1000000000 Tomi,
    100000000 Tomi,
  b> ref,
  nominators_dict dict,              // nominators (pre-seeded)
  withdraw_dict dict,                // withdraw_requests (pre-seeded!)
  0 32 u,
  0 256 u,
  0 8 u,
  0 32 u,
  0 32 u,
  null dict,
b>"""

    code_fift = f'"{_POOL_BOC}" file>B B>boc'

    info = deploy_generic_contract(
        endpoint,
        code_fift=code_fift,
        data_fift=data_fift,
        dest_wc=dest_wc,
        amount_nano=amount_nano,
    )
    info["nominators_count"] = 1
    info["has_withdraw_request"] = True
    return info


# ── Session wallet deployment ──────────────────────────────────────────


def deploy_session_wallet(
    endpoint: str,
    dest_wc: int = 0,
    amount_nano: int = 500_000_000,
) -> dict:
    """Deploy a minimal session wallet with pre-seeded sessions.

    Session entry format: principal(256) + scope(8) + created_at(32) +
    expires_at(32) + revoked(1).

    Two sessions are seeded:
      1. Active, scope=1 (bounded_transfer), expires 2000000000, not revoked.
      2. Revoked, scope=0 (submit_only), revoked=1.
    """
    principal1_hex = "A" * 64
    principal2_hex = "B" * 64

    data_fift = f"""\
dictnew
<b 0x{principal1_hex} 256 u, 1 8 u, 1000000 32 u, 2000000000 32 u, 0 1 u, b> <s
1 rot 32 udict! not abort"cannot add session 1"
<b 0x{principal2_hex} 256 u, 0 8 u, 1000000 32 u, 2000000000 32 u, 1 1 u, b> <s
2 rot 32 udict! not abort"cannot add session 2"
<b swap dict, b>"""

    info = deploy_generic_contract(
        endpoint,
        code_fift='"auto/session-wallet-code.fif" include',
        data_fift=data_fift,
        dest_wc=dest_wc,
        amount_nano=amount_nano,
    )
    info["session_count"] = 2
    return info


# ── Token deployment (Jetton + NFT) ─────────────────────────────────────

JETTON_MINTER_SRC = TOS_ROOT / "crypto/func/auto-tests/legacy_tests/jetton-minter"
JETTON_WALLET_SRC = TOS_ROOT / "crypto/func/auto-tests/legacy_tests/jetton-wallet"
NFT_COLLECTION_SRC = TOS_ROOT / "crypto/func/auto-tests/legacy_tests/nft-collection"
NFT_ITEM_SRC = TOS_ROOT / "crypto/func/auto-tests/legacy_tests/tele-nft-item"


def _compile_func(src_dir: Path, main_file: str) -> Path:
    """Compile a FunC contract, return path to .fif output."""
    out = Path(f"/tmp/{main_file.replace('.fc', '.fif')}")
    result = subprocess.run(
        [str(FUNC_EXE), "-SPA", "-o", str(out), main_file],
        cwd=str(src_dir),
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"func compile failed: {result.stderr}")
    return out


def _ensure_compiled():
    """Compile all token contracts if not already done."""
    contracts = [
        (JETTON_MINTER_SRC, "jetton-minter.fc"),
        (JETTON_WALLET_SRC, "jetton-wallet.fc"),
        (NFT_COLLECTION_SRC, "nft-collection-editable.fc"),
        (NFT_ITEM_SRC, "nft-item.fc"),
    ]
    for src_dir, main_file in contracts:
        out = Path(f"/tmp/{main_file.replace('.fc', '.fif')}")
        if not out.exists():
            _compile_func(src_dir, main_file)


def deploy_jetton_master(endpoint: str, admin_addr: str) -> dict:
    """Deploy a Jetton Master contract. admin_addr is raw format like '0:abc...'."""
    _ensure_compiled()
    parts = admin_addr.split(":")
    admin_wc = int(parts[0])
    admin_hash = parts[1]

    # Data: total_supply(coins=0) + admin_address + content(cell) + wallet_code(cell)
    data_fift = f"""\
<b
  0 Tomi,                                          // total_supply = 0
  b{{10}} s, b{{0}} s, {admin_wc} 8 i, 0x{admin_hash} 256 u, // admin_address
  <b 0 8 u, b> ref,                                // content: onchain marker
  "jetton-wallet-code.boc" file>B B>boc ref,        // jetton_wallet_code
b>"""

    code_fift = '"jetton-minter-code.boc" file>B B>boc'
    return deploy_generic_contract(endpoint, code_fift, data_fift, amount_nano=1_000_000_000)


def deploy_nft_collection(endpoint: str, owner_addr: str) -> dict:
    """Deploy an NFT Collection contract."""
    _ensure_compiled()
    parts = owner_addr.split(":")
    owner_wc = int(parts[0])
    owner_hash = parts[1]

    # Data: owner + next_item_index + content_ref + item_code_ref + royalty_ref
    data_fift = f"""\
<b
  b{{10}} s, b{{0}} s, {owner_wc} 8 i, 0x{owner_hash} 256 u, // owner_address
  0 64 u,                                           // next_item_index = 0
  <b <b 0 8 u, b> ref,                              // collection_content (onchain empty)
     <b 0 8 u, b> ref,                              // common_content
  b> ref,                                            // content cell
  "nft-item-code.boc" file>B B>boc ref,              // nft_item_code
  <b 100 16 u, 1000 16 u,                           // royalty: 10% (100/1000)
     b{{10}} s, b{{0}} s, {owner_wc} 8 i, 0x{owner_hash} 256 u, // royalty_destination
  b> ref,
b>"""

    code_fift = '"nft-collection-code.boc" file>B B>boc'
    return deploy_generic_contract(endpoint, code_fift, data_fift, amount_nano=1_000_000_000)


def deploy_all_tokens(endpoint: str) -> dict:
    """Deploy Jetton master and NFT collection."""
    results = {}

    # Use the first deployed wallet as admin/owner
    cache = _read_cache()
    wallets = cache.get("wallets", {})
    admin_addr = None
    for w in wallets.values():
        if w.get("address"):
            admin_addr = w["address"]
            break
    if not admin_addr:
        admin_addr = MAIN_WALLET_ADDR

    print(f"Using admin address: {admin_addr}")

    print("Deploying jetton_master...")
    try:
        results["jetton_master"] = deploy_jetton_master(endpoint, admin_addr)
        print(f"  -> {results['jetton_master']['address']}")
    except Exception as e:
        print(f"  FAILED: {e}")
        results["jetton_master"] = {"address": None, "error": str(e)}

    print("Deploying nft_collection...")
    try:
        results["nft_collection"] = deploy_nft_collection(endpoint, admin_addr)
        print(f"  -> {results['nft_collection']['address']}")
    except Exception as e:
        print(f"  FAILED: {e}")
        results["nft_collection"] = {"address": None, "error": str(e)}

    return results


# ── Full deployment ──────────────────────────────────────────────────────

CACHE_FILE = Path(__file__).parent / "deployed_addresses.json"


def deploy_all(endpoint: str, force: bool = False) -> dict:
    """Deploy all test contracts, caching results to deployed_addresses.json."""
    if CACHE_FILE.exists() and not force:
        return _read_cache()

    previous = _read_cache()
    all_contracts = {}

    # 1. Wallets
    wallets_result = deploy_all_wallets(endpoint)
    all_contracts["wallets"] = _merge_category_results(previous.get("wallets", {}), wallets_result)

    # 2. Tokens (Jetton + NFT)
    tokens_result = deploy_all_tokens(endpoint)
    all_contracts["tokens"] = _merge_category_results(previous.get("tokens", {}), tokens_result)

    # Save cache without clobbering last-known-good fixtures with failed deploys.
    _write_cache_atomic(all_contracts)
    print(f"\nSaved deployed addresses to {CACHE_FILE}")
    return all_contracts


if __name__ == "__main__":
    import sys
    endpoint = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8011/"
    force = "--force" in sys.argv
    result = deploy_all(endpoint, force=force)
    print(json.dumps(result, indent=2))
