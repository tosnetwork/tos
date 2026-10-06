//! Explicit operating deposits for immutable validator controllers.
//!
//! A controller relays its pool's stake to the elector only against an operating
//! authorization (root action kind 4). Each relayed stake charges the automatic grant
//! against both the recorded funds and the allowance, and is refused once the
//! authorization has expired. This module encodes that authorization, reads it back,
//! prices the grant from the live fee configuration exactly as `stake-relay.fc` does,
//! and plans a renewal by deficit. It never signs: the controller root key is offline.
use crate::{ChainProvider, MasterchainCheckpoint};
use anyhow::Context;
use chain_block::{
    BuilderData, Cell, Coins, ConfigParamEnum, Deserializable, GasLimitsPrices, IBitstring,
    MsgAddressInt, MsgForwardPrices, Serializable,
};
use common::tvm_stack_parser::TvmStackParser;
use tl_api::tos::tvm::StackEntry;

pub const FUND_OPERATIONS_KIND: u8 = 4;
pub const WITHDRAW_OPERATIONS_KIND: u8 = 5;

/// `sr::relay_gas`, `sr::control_gas` and `sr::callback_gas` in `stake-relay.fc`.
pub const RELAY_GAS: u64 = 200_000;
pub const CONTROL_GAS: u64 = 50_000;
pub const CALLBACK_GAS: u64 = 200_000;
/// The fixed message envelope `sr::control_value` and `sr::callback_value` price.
const ENVELOPE_BITS: u64 = 4096;
const ENVELOPE_CELLS: u64 = 8;
/// `sr::coins`: every amount the relay computes is a VarUInteger16.
const COINS_LIMIT: u128 = 1 << 120;
/// `ctl::max_ttl`: how far ahead a root authorization may be valid.
pub const MAX_AUTHORIZATION_TTL: u32 = 3600;
const DAY: u64 = 86_400;

/// All values are explicit; a balance transfer alone never authorizes sponsorship.
/// Monetary values use nano-TOS. The signed request must be sent by `payer`.
pub struct OperatingFunding<'a> {
    pub payer: &'a MsgAddressInt,
    pub deposit: u128,
    pub allowance: u128,
    pub per_request_limit: u128,
    pub storage_floor: u128,
    pub expires_at: u32,
}

/// Payload for the root's existing PQCA signature domain, kind 4. This does not
/// sign or submit a transaction, or choose a deposit/allowance for the operator.
pub fn operating_funding_payload(config: &OperatingFunding<'_>) -> anyhow::Result<Cell> {
    let mut body = BuilderData::new();
    config.payer.write_to(&mut body)?;
    for amount in [config.deposit, config.allowance, config.per_request_limit, config.storage_floor]
    {
        anyhow::ensure!(amount < COINS_LIMIT, "operating amount exceeds VarUInteger16");
        Coins::try_from(amount)?.write_to(&mut body)?;
    }
    body.append_u32(config.expires_at)?;
    body.into_cell()
}

/// Payload for root action kind 5. Only explicitly deposited, unreserved
/// operating funds can be withdrawn, and no relay may remain pending.
pub fn operating_withdrawal_payload(payer: &MsgAddressInt, amount: u128) -> anyhow::Result<Cell> {
    anyhow::ensure!(amount < COINS_LIMIT, "operating amount exceeds VarUInteger16");
    let mut body = BuilderData::new();
    payer.write_to(&mut body)?;
    Coins::try_from(amount)?.write_to(&mut body)?;
    body.into_cell()
}

fn coins(value: u128, what: &str) -> anyhow::Result<u128> {
    anyhow::ensure!(value < COINS_LIMIT, "{what} exceeds the VarUInteger16 range");
    Ok(value)
}

fn add(a: u128, b: u128, what: &str) -> anyhow::Result<u128> {
    coins(a.checked_add(b).ok_or_else(|| anyhow::anyhow!("{what} overflows"))?, what)
}

fn mul(a: u128, b: u128, what: &str) -> anyhow::Result<u128> {
    coins(a.checked_mul(b).ok_or_else(|| anyhow::anyhow!("{what} overflows"))?, what)
}

/// `GETGASFEE` for the masterchain: the flat part, then the remainder at `gas_price`
/// (a 16.16 fixed-point value), rounded up.
pub fn gas_fee(prices: &GasLimitsPrices, gas: u64) -> anyhow::Result<u128> {
    let flat = u128::from(prices.flat_gas_price);
    if gas <= prices.flat_gas_limit {
        return coins(flat, "gas fee");
    }
    let metered = u128::from(gas.saturating_sub(prices.flat_gas_limit))
        .checked_mul(u128::from(prices.gas_price))
        .and_then(|value| value.checked_add(0xffff))
        .ok_or_else(|| anyhow::anyhow!("gas fee overflows"))?
        >> 16;
    add(flat, metered, "gas fee")
}

/// `GETFORWARDFEE` for the masterchain: the lump price plus the per-bit and per-cell
/// prices (16.16 fixed point), rounded up.
pub fn forward_fee(prices: &MsgForwardPrices, bits: u64, cells: u64) -> anyhow::Result<u128> {
    let variable = u128::from(bits)
        .checked_mul(u128::from(prices.bit_price))
        .and_then(|value| {
            u128::from(cells)
                .checked_mul(u128::from(prices.cell_price))
                .and_then(|cell| value.checked_add(cell).and_then(|sum| sum.checked_add(0xffff)))
        })
        .ok_or_else(|| anyhow::anyhow!("forward fee overflows"))?
        >> 16;
    add(u128::from(prices.lump_price), variable, "forward fee")
}

/// The relay's fee constants at one fee configuration, as `stake-relay.fc` derives them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RelayFees {
    /// `sr::control_value()`.
    pub control_value: u128,
    /// `sr::callback_value()`.
    pub callback_value: u128,
    /// `sr::automatic_value()`: what each relayed stake charges against the operating
    /// funds and the allowance, and what the per-request limit must admit.
    pub grant: u128,
    /// What a kind 4 request must carry on top of its deposit:
    /// `gas_fee(-1, relay_gas) + control_value`.
    pub funding_processing: u128,
}

impl RelayFees {
    pub fn from_prices(gas: &GasLimitsPrices, forward: &MsgForwardPrices) -> anyhow::Result<Self> {
        let envelope = forward_fee(forward, ENVELOPE_BITS, ENVELOPE_CELLS)?;
        let control_value = add(gas_fee(gas, CONTROL_GAS)?, envelope, "control value")?;
        let callback_value = add(gas_fee(gas, CALLBACK_GAS)?, envelope, "callback value")?;
        // automatic_value = 3 * control + retry_value, retry_value = control + callback.
        let retry_value = add(control_value, callback_value, "retry value")?;
        let grant = add(mul(3, control_value, "automatic grant")?, retry_value, "automatic grant")?;
        let funding_processing =
            add(gas_fee(gas, RELAY_GAS)?, control_value, "funding processing fee")?;
        Ok(Self { control_value, callback_value, grant, funding_processing })
    }

    /// From live ConfigParam 20 (masterchain gas) and ConfigParam 24 (masterchain
    /// forwarding), which is what `GETGASFEE`/`GETFORWARDFEE` read for workchain -1.
    pub fn from_config(param20: ConfigParamEnum, param24: ConfigParamEnum) -> anyhow::Result<Self> {
        let gas = match param20 {
            ConfigParamEnum::ConfigParam20(value) => value,
            other => anyhow::bail!("live ConfigParam 20 has unexpected representation: {other:?}"),
        };
        let forward = match param24 {
            ConfigParamEnum::ConfigParam24(value) => value,
            other => anyhow::bail!("live ConfigParam 24 has unexpected representation: {other:?}"),
        };
        Self::from_prices(&gas, &forward)
    }
}

/// The controller's `operating_state` getter. A controller that was never funded
/// reports zeros and itself as the payer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatingState {
    pub funds: u128,
    /// The remaining permission, decremented by each grant like the funds.
    pub allowance: u128,
    pub limit: u128,
    pub floor: u128,
    pub expires: u32,
    pub payer: MsgAddressInt,
}

impl OperatingState {
    /// No kind 4 request was ever accepted: the contract reports its own address as the
    /// payer, which no accepted request can record (the sender must be the payer).
    pub fn is_unset(&self, controller: &MsgAddressInt) -> bool {
        self.payer == *controller
    }

    pub fn decode(stack: &TvmStackParser) -> anyhow::Result<Self> {
        anyhow::ensure!(
            stack.stack.len() == 6,
            "operating_state returned {} values, expected 6",
            stack.stack.len()
        );
        let mut payer = stack.slice(5).context("operating payer")?;
        Ok(Self {
            funds: stack_coins(stack, 0).context("operating funds")?,
            allowance: stack_coins(stack, 1).context("operating allowance")?,
            limit: stack_coins(stack, 2).context("per-request limit")?,
            floor: stack_coins(stack, 3).context("storage floor")?,
            expires: u32::try_from(stack.u64(4).context("sponsorship expiry")?)
                .context("sponsorship expiry exceeds uint32")?,
            payer: MsgAddressInt::construct_from(&mut payer).context("parse operating payer")?,
        })
    }
}

/// The parts of `controller_state` a root authorization is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControllerAuthority {
    pub epoch: u64,
    pub nonce: u64,
    pub algorithm: u16,
    pub key_id: [u8; 32],
}

impl ControllerAuthority {
    pub fn decode(stack: &TvmStackParser) -> anyhow::Result<Self> {
        anyhow::ensure!(
            stack.stack.len() == 5,
            "controller_state returned {} values, expected 5",
            stack.stack.len()
        );
        let algorithm = u16::try_from(stack.u64(2).context("consensus algorithm")?)
            .context("consensus algorithm exceeds uint16")?;
        let mut key_id = [0u8; 32];
        key_id.copy_from_slice(&stack.number_bytes(3, 32).context("consensus key id")?);
        Ok(Self {
            epoch: stack.u64(0).context("root epoch")?,
            nonce: stack.u64(1).context("root nonce")?,
            algorithm,
            key_id,
        })
    }
}

fn stack_coins(stack: &TvmStackParser, index: usize) -> anyhow::Result<u128> {
    let text = stack.decimal_string(index)?;
    anyhow::ensure!(!text.starts_with('-'), "negative amount at index {index}: {text}");
    let value = match text.strip_prefix("0x") {
        Some(hex) => u128::from_str_radix(hex, 16),
        None => text.parse::<u128>(),
    }
    .with_context(|| format!("amount at index {index} is not an unsigned integer: {text}"))?;
    coins(value, "amount")
}

/// Whether a `cell` getter result is null. The node renders a null as an empty list
/// (null is the empty list in TVM) or as an unsupported entry.
pub fn stack_entry_is_null(stack: &TvmStackParser, index: usize) -> anyhow::Result<bool> {
    let entry = stack.stack.get(index).ok_or_else(|| {
        anyhow::anyhow!("stack index out of bounds: index={index}, len={}", stack.stack.len())
    })?;
    match entry {
        StackEntry::Tvm_StackEntryUnsupported => Ok(true),
        StackEntry::Tvm_StackEntryList(list) => Ok(list.list.elements().is_empty()),
        StackEntry::Tvm_StackEntryNumber(number) => Ok(number.number.number() == "0"),
        StackEntry::Tvm_StackEntryCell(_) => Ok(false),
        StackEntry::Tvm_StackEntrySlice(_) | StackEntry::Tvm_StackEntryTuple(_) => {
            anyhow::bail!("stack entry {index} is neither a cell nor null")
        }
    }
}

/// When the operating authorization deserves an operator's attention.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct OperatingThresholds {
    /// The runway an authorization is sized for, in seconds.
    pub target_runway_secs: u64,
    /// Warn once the funded runway falls below this percentage of the target.
    pub runway_warn_percent: u8,
    /// Warn once the authorization expires within this many seconds.
    pub expiry_warn_secs: u64,
}

impl Default for OperatingThresholds {
    fn default() -> Self {
        Self { target_runway_secs: 30 * DAY, runway_warn_percent: 25, expiry_warn_secs: 7 * DAY }
    }
}

impl OperatingThresholds {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.target_runway_secs > 0, "the target runway must be positive");
        anyhow::ensure!(
            (1..=100).contains(&self.runway_warn_percent),
            "the runway warning percentage must be between 1 and 100"
        );
        Ok(())
    }

    /// The funded runway below which `RunwayLow` is raised.
    pub fn runway_warn_secs(&self) -> anyhow::Result<u64> {
        self.validate()?;
        self.target_runway_secs
            .checked_mul(u64::from(self.runway_warn_percent))
            .and_then(|value| value.checked_div(100))
            .ok_or_else(|| anyhow::anyhow!("runway threshold overflows"))
    }
}

/// One reason the next relayed stake fails, or soon will.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OperatingWarning {
    /// No operating authorization was ever recorded.
    Missing,
    /// The authorization has expired: every relay fails with exit 180.
    Expired { expired_at: u32 },
    /// The per-request limit does not admit one grant: every relay fails.
    LimitBelowGrant { limit: u128, grant: u128 },
    /// The funds or the allowance no longer cover one grant: the next relay fails.
    CannotCoverNextStake { available: u128, grant: u128 },
    /// The balance does not keep `funds + floor` reserved: the next relay fails.
    CapitalBelowReserve { balance: u128, required: u128 },
    /// A relay is still pending; a renewal must wait for it to finish.
    RelayPending,
    /// The authorization expires within the warning window.
    ExpiresSoon { remaining_secs: u64, threshold_secs: u64 },
    /// The funded runway is below the warning threshold.
    RunwayLow { runway_secs: u64, threshold_secs: u64 },
}

impl OperatingWarning {
    /// Whether the next relayed stake is refused because of this.
    pub fn blocks_next_stake(&self) -> bool {
        matches!(
            self,
            Self::Missing
                | Self::Expired { .. }
                | Self::LimitBelowGrant { .. }
                | Self::CannotCoverNextStake { .. }
                | Self::CapitalBelowReserve { .. }
        )
    }
}

impl std::fmt::Display for OperatingWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => {
                write!(f, "no operating authorization is recorded (kind 4 never accepted)")
            }
            Self::Expired { expired_at } => {
                write!(
                    f,
                    "the operating authorization expired at {expired_at}; every relay fails with exit 180"
                )
            }
            Self::LimitBelowGrant { limit, grant } => write!(
                f,
                "the per-request limit {limit} is below the automatic grant {grant}; every relay fails"
            ),
            Self::CannotCoverNextStake { available, grant } => write!(
                f,
                "funds/allowance {available} do not cover one automatic grant {grant}; the next relay fails"
            ),
            Self::CapitalBelowReserve { balance, required } => write!(
                f,
                "balance {balance} is below funds + floor {required}; the next relay fails"
            ),
            Self::RelayPending => write!(f, "a stake relay is pending"),
            Self::ExpiresSoon { remaining_secs, threshold_secs } => write!(
                f,
                "the operating authorization expires in {remaining_secs} s (warning below {threshold_secs} s)"
            ),
            Self::RunwayLow { runway_secs, threshold_secs } => write!(
                f,
                "the funded runway is {runway_secs} s (warning below {threshold_secs} s); renew by deficit"
            ),
        }
    }
}

/// What the recorded authorization pays for at the current fee configuration.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct OperatingAssessment {
    pub grant: u128,
    /// Relayed stakes `min(funds, allowance)` still pays for.
    pub stakes_remaining: u128,
    /// `stakes_remaining` elections at the elections interval, in seconds.
    pub runway_secs: u64,
    /// Seconds until expiry; zero once expired.
    pub expires_in_secs: u64,
    pub warnings: Vec<OperatingWarning>,
}

impl OperatingAssessment {
    pub fn blocks_next_stake(&self) -> bool {
        self.warnings.iter().any(OperatingWarning::blocks_next_stake)
    }
}

/// Everything a status check needs, read from one chain endpoint.
pub struct OperatingInputs<'a> {
    pub controller: &'a MsgAddressInt,
    pub state: &'a OperatingState,
    pub fees: &'a RelayFees,
    /// The controller's balance, when known.
    pub balance: Option<u128>,
    pub relay_pending: bool,
    pub now: u64,
    /// ConfigParam 15 `validators_elected_for`: one stake per election.
    pub elections_interval_secs: u32,
}

/// Mirrors the relay's own checks (`now < expires`, `grant <= limit`, `grant <=
/// permission`, `grant <= funds`, `balance >= funds + floor`) and adds early warnings.
pub fn assess(
    inputs: &OperatingInputs<'_>,
    thresholds: &OperatingThresholds,
) -> anyhow::Result<OperatingAssessment> {
    let state = inputs.state;
    let grant = inputs.fees.grant;
    anyhow::ensure!(grant > 0, "the automatic grant is zero; the fee configuration is unusable");
    anyhow::ensure!(inputs.elections_interval_secs > 0, "the elections interval is zero");
    let warn_runway = thresholds.runway_warn_secs()?;

    let available = state.funds.min(state.allowance);
    let stakes_remaining =
        available.checked_div(grant).ok_or_else(|| anyhow::anyhow!("division by zero"))?;
    let runway_secs =
        u64::try_from(stakes_remaining.saturating_mul(u128::from(inputs.elections_interval_secs)))
            .unwrap_or(u64::MAX);
    let expires = u64::from(state.expires);
    let expires_in_secs = expires.saturating_sub(inputs.now);

    let mut warnings = Vec::new();
    if state.is_unset(inputs.controller) {
        warnings.push(OperatingWarning::Missing);
    } else if inputs.now >= expires {
        warnings.push(OperatingWarning::Expired { expired_at: state.expires });
    }
    if state.limit < grant {
        warnings.push(OperatingWarning::LimitBelowGrant { limit: state.limit, grant });
    }
    if available < grant {
        warnings.push(OperatingWarning::CannotCoverNextStake { available, grant });
    }
    if let Some(balance) = inputs.balance {
        let required = add(state.funds, state.floor, "funds + floor")?;
        if balance < required {
            warnings.push(OperatingWarning::CapitalBelowReserve { balance, required });
        }
    }
    if inputs.relay_pending {
        warnings.push(OperatingWarning::RelayPending);
    }
    if inputs.now < expires && expires_in_secs < thresholds.expiry_warn_secs {
        warnings.push(OperatingWarning::ExpiresSoon {
            remaining_secs: expires_in_secs,
            threshold_secs: thresholds.expiry_warn_secs,
        });
    }
    if available >= grant && runway_secs < warn_runway {
        warnings.push(OperatingWarning::RunwayLow { runway_secs, threshold_secs: warn_runway });
    }
    Ok(OperatingAssessment { grant, stakes_remaining, runway_secs, expires_in_secs, warnings })
}

/// The funds a runway needs: one grant per election, rounded up to whole elections.
pub fn funds_for_runway(
    fees: &RelayFees,
    runway_secs: u64,
    elections_interval_secs: u32,
) -> anyhow::Result<u128> {
    anyhow::ensure!(elections_interval_secs > 0, "the elections interval is zero");
    let interval = u64::from(elections_interval_secs);
    let elections = runway_secs
        .checked_add(interval.saturating_sub(1))
        .and_then(|value| value.checked_div(interval))
        .ok_or_else(|| anyhow::anyhow!("runway overflows"))?;
    mul(fees.grant, u128::from(elections), "funds target")
}

/// The renewal the operator asks for. Every field but the deposit replaces the stored
/// value; the deposit is derived from the funds target and added.
#[derive(Clone, Debug)]
pub struct RenewalRequest {
    pub payer: MsgAddressInt,
    pub funds_target: u128,
    pub allowance: u128,
    pub limit: u128,
    pub floor: u128,
    pub expires_at: u32,
    /// Extra value the payer sends above what the contract requires; the controller
    /// refunds the change to the payer.
    pub margin: u128,
    pub allow_payer_change: bool,
}

/// A kind 4 request, ready for offline root signing.
#[derive(Clone, Debug)]
pub struct RenewalPlan {
    pub deposit: u128,
    pub funds_after: u128,
    pub allowance: u128,
    pub limit: u128,
    pub floor: u128,
    pub expires_at: u32,
    pub payer: MsgAddressInt,
    /// What the contract requires the payer's message to carry:
    /// `deposit + gas_fee(-1, relay_gas) + control_value`.
    pub required_value: u128,
    /// `required_value` plus the margin.
    pub message_value: u128,
    pub payload: Cell,
    /// The controller's balance once the request is accepted: the contract reserves
    /// the prior balance plus the deposit and refunds the rest.
    pub capital_after: u128,
    /// A plain transfer the controller still needs so that `balance >= funds + floor`
    /// holds for the next relay. The deposit cannot supply it: it raises the balance
    /// and the recorded funds by the same amount.
    pub capital_top_up: u128,
}

impl RenewalPlan {
    /// The authorization this request installs, as `operating_state` will report it.
    pub fn projected_state(&self) -> OperatingState {
        OperatingState {
            funds: self.funds_after,
            allowance: self.allowance,
            limit: self.limit,
            floor: self.floor,
            expires: self.expires_at,
            payer: self.payer.clone(),
        }
    }
}

/// Plans a renewal by deficit: `deposit = max(0, funds_target - funds)`, because the
/// contract adds the deposit to the recorded funds and replaces every other field.
/// A target at or below the current funds is a zero-deposit renewal (for example,
/// only the expiry moves).
pub fn plan_renewal(
    controller: &MsgAddressInt,
    state: &OperatingState,
    balance: u128,
    fees: &RelayFees,
    relay_pending: bool,
    now: u64,
    request: &RenewalRequest,
) -> anyhow::Result<RenewalPlan> {
    anyhow::ensure!(
        !relay_pending,
        "a stake relay is pending on this controller; wait for it to finish before renewing"
    );
    if !state.is_unset(controller) && state.payer != request.payer && !request.allow_payer_change {
        anyhow::bail!(
            "the recorded payer is {} and this renewal names {}; pass the explicit payer-change \
             option to move sponsorship to another wallet",
            state.payer,
            request.payer
        );
    }
    anyhow::ensure!(
        request.payer != *controller,
        "the controller cannot be its own operating payer"
    );
    anyhow::ensure!(
        u64::from(request.expires_at) > now,
        "the requested expiry {} is not in the future (now {now})",
        request.expires_at
    );
    let grant = fees.grant;
    anyhow::ensure!(
        request.limit >= grant,
        "the per-request limit {} is below the automatic grant {grant}; every relay would fail",
        request.limit
    );
    anyhow::ensure!(
        request.allowance >= grant,
        "the allowance {} is below the automatic grant {grant}; no relay could be paid",
        request.allowance
    );
    for (value, what) in [
        (request.funds_target, "funds target"),
        (request.allowance, "allowance"),
        (request.limit, "per-request limit"),
        (request.floor, "storage floor"),
        (request.margin, "margin"),
    ] {
        coins(value, what)?;
    }

    let deposit = request.funds_target.saturating_sub(state.funds);
    let funds_after = add(state.funds, deposit, "resulting funds")?;
    anyhow::ensure!(
        funds_after >= grant,
        "the resulting funds {funds_after} do not cover one automatic grant {grant}"
    );
    let required_value = add(deposit, fees.funding_processing, "required message value")?;
    let message_value = add(required_value, request.margin, "message value")?;
    let capital_after = add(balance, deposit, "balance after the deposit")?;
    let capital_top_up =
        add(funds_after, request.floor, "funds + floor")?.saturating_sub(capital_after);
    let payload = operating_funding_payload(&OperatingFunding {
        payer: &request.payer,
        deposit,
        allowance: request.allowance,
        per_request_limit: request.limit,
        storage_floor: request.floor,
        expires_at: request.expires_at,
    })?;
    Ok(RenewalPlan {
        deposit,
        funds_after,
        allowance: request.allowance,
        limit: request.limit,
        floor: request.floor,
        expires_at: request.expires_at,
        payer: request.payer.clone(),
        required_value,
        message_value,
        payload,
        capital_after,
        capital_top_up,
    })
}

/// The latest `valid_until` an authorization prepared at `now` may carry: the contract
/// refuses anything later than `now + MAX_AUTHORIZATION_TTL`.
pub fn authorization_valid_until(now: u64, valid_for_secs: u32) -> anyhow::Result<u32> {
    anyhow::ensure!(
        (1..=MAX_AUTHORIZATION_TTL).contains(&valid_for_secs),
        "an authorization may be valid for 1 to {MAX_AUTHORIZATION_TTL} seconds"
    );
    let until = now
        .checked_add(u64::from(valid_for_secs))
        .ok_or_else(|| anyhow::anyhow!("valid_until overflows"))?;
    u32::try_from(until).context("valid_until exceeds uint32")
}

/// A controller's operating authorization as one chain endpoint reports it.
#[derive(Clone, Debug)]
pub struct ControllerOperations {
    pub authority: ControllerAuthority,
    pub state: OperatingState,
    pub relay_pending: bool,
    /// Retry fees are held for an unfinished relay; treated like a pending relay.
    pub retry_fees_held: bool,
    pub balance: u128,
    pub fees: RelayFees,
    pub elections_interval_secs: u32,
    /// The masterchain block every value above was read at.
    pub checkpoint: MasterchainCheckpoint,
}

/// The current masterchain head, as a checkpoint to pin reads to.
pub async fn latest_checkpoint(chain: &dyn ChainProvider) -> anyhow::Result<MasterchainCheckpoint> {
    let last = chain.get_masterchain_info().await?.last;
    anyhow::ensure!(last.workchain == -1, "the masterchain head is not a masterchain block");
    Ok(MasterchainCheckpoint {
        seqno: last.seqno,
        root_hash: hex::encode(&last.root_hash),
        file_hash: hex::encode(&last.file_hash),
    })
}

/// Reads the getters and the fee configuration a status check or a renewal needs,
/// all at the current masterchain head: one block, so a relay landing between two
/// reads cannot make them disagree. Activity after that block can still change them.
pub async fn read_controller_operations(
    chain: &dyn ChainProvider,
    controller: &MsgAddressInt,
) -> anyhow::Result<ControllerOperations> {
    let checkpoint = latest_checkpoint(chain).await?;
    read_controller_operations_at(chain, controller, checkpoint).await
}

/// [`read_controller_operations`] at an explicit checkpoint.
pub async fn read_controller_operations_at(
    chain: &dyn ChainProvider,
    controller: &MsgAddressInt,
    checkpoint: MasterchainCheckpoint,
) -> anyhow::Result<ControllerOperations> {
    anyhow::ensure!(
        controller.workchain_id() == -1,
        "a validator controller is a masterchain account"
    );
    let address = controller.to_string();
    let getter = |method: &'static str| {
        chain.run_get_method_at_unverified(address.clone(), method, vec![], &checkpoint)
    };
    let authority = ControllerAuthority::decode(&getter("controller_state").await?)?;
    let state = OperatingState::decode(&getter("operating_state").await?)?;
    let pending = getter("relay_pending").await?;
    let relay_pending = !stack_entry_is_null(&pending, 0).context("relay_pending")?;
    let retry = getter("relay_retry_fees").await?;
    let retry_fees_held = !stack_entry_is_null(&retry, 0).context("relay_retry_fees")?;
    let balance = u128::from(chain.get_balance_at_unverified(controller, &checkpoint).await?);
    let fees = RelayFees::from_config(
        chain.get_config_param_at_unverified(20, &checkpoint).await?,
        chain.get_config_param_at_unverified(24, &checkpoint).await?,
    )?;
    let elections_interval_secs =
        match chain.get_config_param_at_unverified(15, &checkpoint).await? {
            ConfigParamEnum::ConfigParam15(value) => value.validators_elected_for,
            other => anyhow::bail!("live ConfigParam 15 has unexpected representation: {other:?}"),
        };
    Ok(ControllerOperations {
        authority,
        state,
        relay_pending,
        retry_fees_held,
        balance,
        fees,
        elections_interval_secs,
        checkpoint,
    })
}

impl ControllerOperations {
    pub fn assess(
        &self,
        controller: &MsgAddressInt,
        now: u64,
        thresholds: &OperatingThresholds,
    ) -> anyhow::Result<OperatingAssessment> {
        assess(
            &OperatingInputs {
                controller,
                state: &self.state,
                fees: &self.fees,
                balance: Some(self.balance),
                relay_pending: self.relay_pending || self.retry_fees_held,
                now,
                elections_interval_secs: self.elections_interval_secs,
            },
            thresholds,
        )
    }
}

#[cfg(test)]
#[path = "validator_controller_tests.rs"]
mod tests;
