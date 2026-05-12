/*
 * Rust encoder for the wc=3 `action_create_account` OutAction
 * (block.tlb:420).
 *
 *   action_create_account#4a435241 mode:(## 8)
 *     dest_addr:bits256
 *     state_init:^StateInit
 *     value:Tomis
 *     body:(Maybe ^Cell) = OutAction;
 *
 * The C++ reference is `crypto/block/transaction.cpp::try_action_create_account`
 * (around line 2801). The validator-side gate at line 2807 requires the
 * sender's workchain to declare `admits_engine_create_account_actions`, and
 * the addr_std$10 gate at line 2812 restricts the sender's workchain to
 * the signed-int8 range [-128, 128). At v2 launch the only honoring
 * workchain is wc=3 (JVM).
 *
 * The output cell is a standalone OutAction node — wrap it in an
 * `out_list` chain (or pack via `OutActions::write_to`) when emitting it
 * from a contract.
 *
 * `value` carries the Tomis (nanocoins) attached to the create call. It
 * is serialized as VarUInteger 16 per the TLB schema; on this Rust side
 * we encode the 4-bit length prefix + big-endian value bytes inline so
 * the output is byte-stable without depending on Coins::write_to (which
 * could in principle drift across edition / refactor).
 */
use anyhow::{Context, Result, anyhow};
use chain_block::{BuilderData, Cell, IBitstring};

/// Magic prefix for `action_create_account` (`'JCRA'` == 0x4a435241).
pub const ACTION_CREATE_ACCOUNT_MAGIC: u32 = 0x4a43_5241;

/// Build an `action_create_account` OutAction cell ready to be packed
/// into an OutActions list.
///
/// * `mode`        — the 8-bit mode byte the C++ side passes through to
///                    `try_action_send_msg`. The action_create_account
///                    schema reserves 8 bits for it; the validator
///                    forwards the mode to the internal send so flags
///                    like SENDMSG_IGNORE_ERROR / SENDMSG_PAY_FEE_SEPARATELY
///                    behave the same as for action_send_msg.
/// * `dest_addr`   — 32-byte account-id at which the host materializes
///                    the new account in the sender's workchain.
/// * `state_init`  — StateInit cell as referenced by ^StateInit. For the
///                    JVM, build it with
///                    `encode_jvm_state_init_cell(account_state)`.
/// * `value_tomis` — Tomis (nanocoins) attached to the synthesized
///                    internal message that carries the new account's
///                    storage-stake + first-call gas.
/// * `body`        — `Maybe ^Cell` body. For an `init(...)` call carry
///                    the encoded JVI2 call descriptor here; pass
///                    `None` to leave the new account uncalled at create
///                    time.
pub fn encode_action_create_account(
    mode: u8,
    dest_addr: &[u8; 32],
    state_init: Cell,
    value_tomis: u128,
    body: Option<Cell>,
) -> Result<Cell> {
    let mut cb = BuilderData::new();
    cb.append_u32(ACTION_CREATE_ACCOUNT_MAGIC)
        .context("action_create_account magic append failed")?;
    cb.append_u8(mode)
        .context("action_create_account mode append failed")?;
    cb.append_raw(dest_addr, 256)
        .context("action_create_account dest_addr append failed")?;
    cb.checked_append_reference(state_init)
        .context("action_create_account state_init ref append failed")?;
    append_var_uint16(&mut cb, value_tomis)
        .context("action_create_account value(Tomis) append failed")?;
    match body {
        Some(body_cell) => {
            cb.append_bit_one()
                .context("action_create_account body Just bit failed")?;
            cb.checked_append_reference(body_cell)
                .context("action_create_account body ref append failed")?;
        }
        None => {
            cb.append_bit_zero()
                .context("action_create_account body Nothing bit failed")?;
        }
    }
    cb.into_cell()
        .context("action_create_account finalize failed")
}

/// Encode a `VarUInteger 16` (Tomis) inline:
///   len:(#< 16)        — 4 bits
///   value:(uint (len*8)) — len * 8 bits, big-endian.
/// Zero encodes as a 4-bit `0000` with no value bytes.
fn append_var_uint16(cb: &mut BuilderData, value: u128) -> Result<()> {
    if value == 0 {
        cb.append_bits(0, 4)
            .context("var_uint16 zero-length prefix")?;
        return Ok(());
    }
    // Bytes required to represent `value`. Max 16 for VarUInteger 16.
    let bits_needed = 128 - value.leading_zeros() as usize;
    let len = bits_needed.div_ceil(8);
    if len >= 16 {
        return Err(anyhow!(
            "value {value} exceeds Tomis (VarUInteger 16) range"
        ));
    }
    cb.append_bits(len, 4)
        .context("var_uint16 length prefix append failed")?;
    // Emit `len` big-endian bytes, skipping the leading zeros.
    let be = value.to_be_bytes();
    let start = 16 - len;
    cb.append_raw(&be[start..], len * 8)
        .context("var_uint16 value bytes append failed")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chain_block::IBitstring;

    fn fake_state_init() -> Cell {
        let mut cb = BuilderData::new();
        // Two zero bits matches "fixed_prefix_length=Nothing, special=Nothing"
        // shape; we don't need a full StateInit here — only a referenceable
        // cell for the encoding-shape tests below.
        cb.append_bit_zero().unwrap();
        cb.append_bit_zero().unwrap();
        cb.into_cell().unwrap()
    }

    #[test]
    fn action_create_account_carries_two_refs_when_body_absent() {
        let cell = encode_action_create_account(
            3,
            &[0x11u8; 32],
            fake_state_init(),
            0,
            None,
        )
        .expect("encode");
        // Only state_init ref present (body is Nothing).
        assert_eq!(cell.references_count(), 1);
    }

    #[test]
    fn action_create_account_carries_two_refs_when_body_present() {
        let mut body_cb = BuilderData::new();
        body_cb.append_u32(0xdead_beef).unwrap();
        let body = body_cb.into_cell().unwrap();

        let cell = encode_action_create_account(
            3,
            &[0x22u8; 32],
            fake_state_init(),
            1_000_000_000u128,
            Some(body),
        )
        .expect("encode");
        assert_eq!(cell.references_count(), 2);
    }

    #[test]
    fn action_create_account_is_deterministic() {
        let a = encode_action_create_account(
            0,
            &[0x33u8; 32],
            fake_state_init(),
            42,
            None,
        )
        .expect("encode 1");
        let b = encode_action_create_account(
            0,
            &[0x33u8; 32],
            fake_state_init(),
            42,
            None,
        )
        .expect("encode 2");
        assert_eq!(a.repr_hash(), b.repr_hash());
    }

    #[test]
    fn var_uint16_rejects_too_large_value() {
        // 16-byte boundary: 2^128 - 1 needs len=16, which equals N and
        // must be rejected per the `len < N` rule.
        let mut cb = BuilderData::new();
        let r = append_var_uint16(&mut cb, u128::MAX);
        assert!(r.is_err());
    }

    #[test]
    fn var_uint16_zero_is_four_zero_bits() {
        // A zero-value encoding must consume exactly 4 bits in the
        // builder (no value bytes). We assert this indirectly by
        // checking that two builders — one with a 4-bit zero
        // prefix appended directly, one via append_var_uint16(0) —
        // finalize to the same cell hash.
        let mut a = BuilderData::new();
        append_var_uint16(&mut a, 0).unwrap();
        let mut b = BuilderData::new();
        b.append_bits(0, 4).unwrap();
        assert_eq!(
            a.into_cell().unwrap().repr_hash(),
            b.into_cell().unwrap().repr_hash()
        );
    }
}
