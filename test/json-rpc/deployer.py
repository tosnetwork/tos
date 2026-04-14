"""
Contract deployer for TOS JSON-RPC test suite.

Deploys wallet, Jetton, NFT, and DNS contracts on a live TOS testnet using
the pre-funded main wallet at -1:000...000.  All deployment happens via Fift
scripts + the JSON-RPC ``sendBoc`` endpoint — no lite-client needed.
"""
import base64
import json
import os
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
  b{{0}} s,                  // body: empty
b> constant int_msg

// Payload: seqno(32) + mode(8) + internal_msg_ref
<b mw_seqno 32 u, 3 8 u, int_msg ref, b>
dup constant payload
dup hashu mw_pk ed25519_sign_uint constant signature

// External message to main wallet (-1:000...000)
<b b{{1000100}} s,
   -1 Masterchain 0 addr,
   0 Tomi, b{{00}} s,
   b{{1}} s,
   <b signature B, payload <s s, b> ref,
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
    import shutil
    shutil.copy(str(MAIN_WALLET_PK), str(working_dir / "main-wallet.pk"))

    # Copy compiled BOC files for code references
    for boc in ["/tmp/jetton-minter-code.boc", "/tmp/jetton-wallet-code.boc",
                "/tmp/nft-collection-code.boc", "/tmp/nft-item-code.boc"]:
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
    cache = json.loads(CACHE_FILE.read_text()) if CACHE_FILE.exists() else {}
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
        return json.loads(CACHE_FILE.read_text())

    all_contracts = {}

    # 1. Wallets
    all_contracts["wallets"] = deploy_all_wallets(endpoint)

    # 2. Tokens (Jetton + NFT)
    all_contracts["tokens"] = deploy_all_tokens(endpoint)

    # Save cache
    CACHE_FILE.write_text(json.dumps(all_contracts, indent=2))
    print(f"\nSaved deployed addresses to {CACHE_FILE}")
    return all_contracts


if __name__ == "__main__":
    import sys
    endpoint = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8011/"
    force = "--force" in sys.argv
    result = deploy_all(endpoint, force=force)
    print(json.dumps(result, indent=2))
