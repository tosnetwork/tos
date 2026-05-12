/*
 * Rust port of `encode_jvm_state_init_cell` (jvm/core/cell-codec.cpp).
 *
 * Builds the StateInit cell consumed by `action_create_account`:
 *
 *   StateInit {
 *     fixed_prefix_length = Nothing      (1 bit "0")
 *     special             = Nothing      (1 bit "0")
 *     code                = Just ^marker (1 bit "1" + ref)
 *     data                = Just ^state  (1 bit "1" + ref)
 *     library             = hme_empty$0  (1 bit "0")
 *   }
 *
 * `marker` is a single-byte cell carrying the wc=3 activation code
 * (0x4a, 'J'). `state` is the JvmContractAccountState (JVAC) cell the
 * caller built — typically by talking to `jvm_deployContract` RPC and
 * decoding the returned deploy-descriptor BOC; the validator handles
 * the JVAC build server-side.
 */
use anyhow::{Context, Result};
use chain_block::{BuilderData, Cell, IBitstring};

use super::JVM_ACTIVATION_CODE_MARKER;

pub fn encode_jvm_state_init_cell(state_cell: Cell) -> Result<Cell> {
    let mut code_cb = BuilderData::new();
    code_cb
        .append_u8(JVM_ACTIVATION_CODE_MARKER)
        .context("jvm state_init: activation marker append failed")?;
    let code_cell = code_cb
        .into_cell()
        .context("jvm state_init: activation marker finalize failed")?;

    let mut cb = BuilderData::new();
    cb.append_bit_zero()
        .context("jvm state_init: fixed_prefix_length bit failed")?;
    cb.append_bit_zero()
        .context("jvm state_init: special bit failed")?;
    cb.append_bit_one()
        .context("jvm state_init: code present bit failed")?;
    cb.checked_append_reference(code_cell)
        .context("jvm state_init: code ref append failed")?;
    cb.append_bit_one()
        .context("jvm state_init: data present bit failed")?;
    cb.checked_append_reference(state_cell)
        .context("jvm state_init: data ref append failed")?;
    cb.append_bit_zero()
        .context("jvm state_init: empty-library bit failed")?;
    cb.into_cell()
        .context("jvm state_init finalize failed")
}
