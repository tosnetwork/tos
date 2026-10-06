use super::*;
use chain_block::{SliceData, write_boc};
use tl_api::tos::tvm::{
    List, Number, cell as tl_cell, list,
    numberdecimal::NumberDecimal,
    slice as tl_slice,
    stackentry::{StackEntryCell, StackEntryList, StackEntryNumber, StackEntrySlice},
};

const NANO: u128 = 1_000_000_000;
const NOW: u64 = 1_791_250_000;
const ELECTED_FOR: u32 = 65_536;

/// The fee fixture of the local funding helper's tests (`prices()`): a flat prefix of
/// 100 gas for 1_000_000, then `gas_price` per 2^16 gas; forwarding with lump 10^7, bit
/// price 655_360_000 and cell price 65_536_000_000 (16.16 fixed point).
fn gas(flat: bool, gas_price: u64) -> GasLimitsPrices {
    GasLimitsPrices {
        gas_price,
        gas_limit: 1_000_000,
        special_gas_limit: 1_000_000,
        gas_credit: 10_000,
        block_gas_limit: 10_000_000,
        freeze_due_limit: 100_000_000,
        delete_due_limit: 1_000_000_000,
        flat_gas_limit: if flat { 100 } else { 0 },
        flat_gas_price: if flat { 1_000_000 } else { 0 },
        ..Default::default()
    }
}

fn forward() -> MsgForwardPrices {
    MsgForwardPrices {
        lump_price: 10_000_000,
        bit_price: 655_360_000,
        cell_price: 65_536_000_000,
        ihr_price_factor: 98_304,
        first_frac: 21_845,
        next_frac: 21_845,
    }
}

fn fees() -> RelayFees {
    RelayFees::from_prices(&gas(true, 10_000 * 65_536), &forward()).unwrap()
}

/// Values printed by the local network's Python `fee_budget` (the reference
/// implementation of the same FunC formulas) for the same configurations:
/// `(flat, gas_price, grant, processing)`.
const PYTHON_REFERENCE: [(bool, u64, u128, u128); 6] = [
    (true, 655_360_000, 4_294_800_000, 2_558_960_000),
    (true, 65_536_000, 699_300_000, 310_760_000),
    (true, 809_042_697, 5_231_632_239, 3_144_743_963),
    (false, 655_360_000, 4_294_800_000, 2_558_960_000),
    (false, 65_536_000, 694_800_000, 308_960_000),
    (false, 809_042_697, 5_232_804_744, 3_145_212_965),
];

#[test]
fn relay_fees_match_the_python_reference_values() {
    for (flat, gas_price, grant, processing) in PYTHON_REFERENCE {
        let value = RelayFees::from_prices(&gas(flat, gas_price), &forward()).unwrap();
        assert_eq!(value.grant, grant, "grant flat={flat} gas_price={gas_price}");
        assert_eq!(
            value.funding_processing, processing,
            "processing flat={flat} gas_price={gas_price}"
        );
    }
}

#[test]
fn relay_fees_expand_the_func_formulas() {
    // Independent integer expansion, as in the reference tests.
    let ff: u128 = 10_000_000 + 4096 * 10_000 + 8 * 1_000_000;
    let control = 1_000_000 + (50_000 - 100) * 10_000 + ff;
    let callback = 1_000_000 + (200_000 - 100) * 10_000 + ff;
    let value = fees();
    assert_eq!(value.control_value, control);
    assert_eq!(value.callback_value, callback);
    assert_eq!(value.grant, 4 * control + callback);
    assert_eq!(value.funding_processing, 1_000_000 + (200_000 - 100) * 10_000 + control);
}

#[test]
fn gas_fee_rounds_up_and_honours_the_flat_part() {
    let prices = gas(true, 3);
    assert_eq!(gas_fee(&prices, 0).unwrap(), 1_000_000);
    assert_eq!(gas_fee(&prices, 100).unwrap(), 1_000_000);
    // One metered unit at 3/65536 rounds up to one nano.
    assert_eq!(gas_fee(&prices, 101).unwrap(), 1_000_001);
    let fwd = MsgForwardPrices { lump_price: 7, bit_price: 1, cell_price: 0, ..forward() };
    assert_eq!(forward_fee(&fwd, 1, 0).unwrap(), 8);
    assert_eq!(forward_fee(&fwd, 0, 0).unwrap(), 7);
}

#[test]
fn fees_outside_the_coins_range_are_refused() {
    let prices = GasLimitsPrices { gas_price: u64::MAX, ..gas(false, 0) };
    let fwd = MsgForwardPrices { lump_price: u64::MAX, ..forward() };
    // Large but representable; the grant still fits, so it is computed.
    assert!(RelayFees::from_prices(&prices, &fwd).is_ok());
    assert!(coins(COINS_LIMIT, "x").is_err());
    assert!(add(COINS_LIMIT - 1, 1, "x").is_err());
}

#[test]
fn live_config_must_be_the_matching_parameters() {
    let ok = RelayFees::from_config(
        ConfigParamEnum::ConfigParam20(gas(true, 10_000 * 65_536)),
        ConfigParamEnum::ConfigParam24(forward()),
    )
    .unwrap();
    assert_eq!(ok, fees());
    let wrong = RelayFees::from_config(
        ConfigParamEnum::ConfigParam21(gas(true, 1)),
        ConfigParamEnum::ConfigParam24(forward()),
    );
    assert!(wrong.unwrap_err().to_string().contains("ConfigParam 20"));
}

fn controller() -> MsgAddressInt {
    MsgAddressInt::standard(-1, [0xC0; 32])
}

fn payer() -> MsgAddressInt {
    MsgAddressInt::standard(-1, [0xAA; 32])
}

fn state(funds: u128, allowance: u128) -> OperatingState {
    OperatingState {
        funds,
        allowance,
        limit: 20 * NANO,
        floor: 10 * NANO,
        expires: (NOW + 30 * DAY) as u32,
        payer: payer(),
    }
}

fn request(funds_target: u128) -> RenewalRequest {
    RenewalRequest {
        payer: payer(),
        funds_target,
        allowance: funds_target,
        limit: 20 * NANO,
        floor: 10 * NANO,
        expires_at: (NOW + 60 * DAY) as u32,
        margin: NANO,
        allow_payer_change: false,
    }
}

#[test]
fn renewal_deposits_only_the_deficit() {
    let fees = fees();
    let plan = plan_renewal(
        &controller(),
        &state(30 * NANO, 5 * NANO),
        &fees,
        false,
        NOW,
        &request(100 * NANO),
    )
    .unwrap();
    assert_eq!(plan.deposit, 70 * NANO);
    assert_eq!(plan.funds_after, 100 * NANO);
    assert_eq!(plan.allowance, 100 * NANO, "the allowance is replaced, not added");
    assert_eq!(plan.required_value, 70 * NANO + fees.funding_processing);
    assert_eq!(plan.message_value, plan.required_value + NANO);
}

#[test]
fn a_surplus_renews_with_a_zero_deposit() {
    let fees = fees();
    let mut ask = request(100 * NANO);
    ask.expires_at = (NOW + 90 * DAY) as u32;
    let plan = plan_renewal(&controller(), &state(150 * NANO, 1), &fees, false, NOW, &ask).unwrap();
    assert_eq!(plan.deposit, 0);
    assert_eq!(plan.funds_after, 150 * NANO);
    assert_eq!(plan.expires_at, ask.expires_at);
    assert_eq!(plan.required_value, fees.funding_processing);
    // Exactly at the target is also zero.
    let plan = plan_renewal(&controller(), &state(100 * NANO, 1), &fees, false, NOW, &ask).unwrap();
    assert_eq!(plan.deposit, 0);
}

#[test]
fn the_payload_is_the_layout_the_contract_parses() {
    let plan = plan_renewal(
        &controller(),
        &state(30 * NANO, 0),
        &fees(),
        false,
        NOW,
        &request(100 * NANO),
    )
    .unwrap();
    let mut slice = SliceData::load_cell(plan.payload).unwrap();
    assert_eq!(MsgAddressInt::construct_from(&mut slice).unwrap(), payer());
    for expected in [70 * NANO, 100 * NANO, 20 * NANO, 10 * NANO] {
        let value = Coins::construct_from(&mut slice).unwrap();
        assert_eq!(value.as_u128(), expected);
    }
    assert_eq!(slice.get_next_u32().unwrap(), (NOW + 60 * DAY) as u32);
    assert_eq!(slice.remaining_bits(), 0);
    assert_eq!(slice.remaining_references(), 0);
}

#[test]
fn renewal_refusals() {
    let fees = fees();
    let current = state(30 * NANO, 30 * NANO);
    let pending = plan_renewal(&controller(), &current, &fees, true, NOW, &request(100 * NANO));
    assert!(pending.unwrap_err().to_string().contains("pending"));

    let mut other = request(100 * NANO);
    other.payer = MsgAddressInt::standard(-1, [0xBB; 32]);
    let refused = plan_renewal(&controller(), &current, &fees, false, NOW, &other);
    assert!(refused.unwrap_err().to_string().contains("recorded payer"));
    other.allow_payer_change = true;
    assert!(plan_renewal(&controller(), &current, &fees, false, NOW, &other).is_ok());

    // A controller never funded reports itself as payer; any payer may start.
    let unset = OperatingState { payer: controller(), expires: 0, ..state(0, 0) };
    let mut first = request(100 * NANO);
    first.payer = MsgAddressInt::standard(-1, [0xBB; 32]);
    assert!(plan_renewal(&controller(), &unset, &fees, false, NOW, &first).is_ok());
    first.payer = controller();
    assert!(plan_renewal(&controller(), &unset, &fees, false, NOW, &first).is_err());

    let mut low_limit = request(100 * NANO);
    low_limit.limit = fees.grant - 1;
    let refused = plan_renewal(&controller(), &current, &fees, false, NOW, &low_limit);
    assert!(refused.unwrap_err().to_string().contains("per-request limit"));
    low_limit.limit = fees.grant;
    assert!(plan_renewal(&controller(), &current, &fees, false, NOW, &low_limit).is_ok());

    let mut low_allowance = request(100 * NANO);
    low_allowance.allowance = fees.grant - 1;
    let refused = plan_renewal(&controller(), &current, &fees, false, NOW, &low_allowance);
    assert!(refused.unwrap_err().to_string().contains("allowance"));

    let mut past = request(100 * NANO);
    past.expires_at = NOW as u32;
    let refused = plan_renewal(&controller(), &current, &fees, false, NOW, &past);
    assert!(refused.unwrap_err().to_string().contains("not in the future"));

    let tiny = plan_renewal(
        &controller(),
        &state(0, 0),
        &fees,
        false,
        NOW,
        &RenewalRequest { funds_target: fees.grant - 1, allowance: fees.grant, ..request(0) },
    );
    assert!(tiny.unwrap_err().to_string().contains("do not cover one automatic grant"));

    let mut huge = request(COINS_LIMIT - 1);
    huge.margin = COINS_LIMIT - 1;
    assert!(plan_renewal(&controller(), &state(0, 0), &fees, false, NOW, &huge).is_err());
}

fn inputs<'a>(
    state: &'a OperatingState,
    fees: &'a RelayFees,
    controller: &'a MsgAddressInt,
) -> OperatingInputs<'a> {
    OperatingInputs {
        controller,
        state,
        fees,
        balance: Some(1_000_000 * NANO),
        relay_pending: false,
        now: NOW,
        elections_interval_secs: ELECTED_FOR,
    }
}

fn thresholds() -> OperatingThresholds {
    OperatingThresholds {
        target_runway_secs: 100 * u64::from(ELECTED_FOR),
        runway_warn_percent: 25,
        expiry_warn_secs: 7 * DAY,
    }
}

#[test]
fn runway_is_whole_stakes_at_the_elections_interval() {
    let fees = fees();
    let current = state(10 * fees.grant + fees.grant - 1, 1_000 * fees.grant);
    let ctl = controller();
    let report = assess(&inputs(&current, &fees, &ctl), &thresholds()).unwrap();
    assert_eq!(report.stakes_remaining, 10);
    assert_eq!(report.runway_secs, 10 * u64::from(ELECTED_FOR));
    // The allowance caps the runway as well.
    let current = state(1_000 * fees.grant, 3 * fees.grant);
    let report = assess(&inputs(&current, &fees, &ctl), &thresholds()).unwrap();
    assert_eq!(report.stakes_remaining, 3);
}

#[test]
fn runway_warning_edges() {
    let fees = fees();
    let ctl = controller();
    // Threshold: 25% of 100 elections = 25 elections.
    let at = state(25 * fees.grant, 25 * fees.grant);
    let report = assess(&inputs(&at, &fees, &ctl), &thresholds()).unwrap();
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    let below = state(25 * fees.grant - 1, 25 * fees.grant);
    let report = assess(&inputs(&below, &fees, &ctl), &thresholds()).unwrap();
    assert_eq!(
        report.warnings,
        vec![OperatingWarning::RunwayLow {
            runway_secs: 24 * u64::from(ELECTED_FOR),
            threshold_secs: 25 * u64::from(ELECTED_FOR),
        }]
    );
    assert!(!report.blocks_next_stake());
}

#[test]
fn expiry_warning_edges() {
    let fees = fees();
    let ctl = controller();
    let mut current = state(1_000 * fees.grant, 1_000 * fees.grant);
    current.expires = (NOW + 7 * DAY) as u32;
    let report = assess(&inputs(&current, &fees, &ctl), &thresholds()).unwrap();
    assert!(report.warnings.is_empty(), "{:?}", report.warnings);

    current.expires = (NOW + 7 * DAY - 1) as u32;
    let report = assess(&inputs(&current, &fees, &ctl), &thresholds()).unwrap();
    assert_eq!(
        report.warnings,
        vec![OperatingWarning::ExpiresSoon {
            remaining_secs: 7 * DAY - 1,
            threshold_secs: 7 * DAY
        }]
    );

    // The relay requires now < expires: at expiry it already fails.
    current.expires = NOW as u32;
    let report = assess(&inputs(&current, &fees, &ctl), &thresholds()).unwrap();
    assert_eq!(report.warnings, vec![OperatingWarning::Expired { expired_at: NOW as u32 }]);
    assert!(report.blocks_next_stake());
    assert_eq!(report.expires_in_secs, 0);
}

#[test]
fn blocking_conditions_mirror_the_relay_checks() {
    let fees = fees();
    let ctl = controller();

    let unset = OperatingState { payer: controller(), expires: 0, ..state(0, 0) };
    let mut unset = unset;
    unset.limit = 0;
    unset.floor = 0;
    let report = assess(&inputs(&unset, &fees, &ctl), &thresholds()).unwrap();
    assert_eq!(report.warnings[0], OperatingWarning::Missing);
    assert!(
        report
            .warnings
            .contains(&OperatingWarning::LimitBelowGrant { limit: 0, grant: fees.grant })
    );
    assert!(
        report
            .warnings
            .contains(&OperatingWarning::CannotCoverNextStake { available: 0, grant: fees.grant })
    );
    assert!(report.blocks_next_stake());

    let mut limited = state(1_000 * fees.grant, 1_000 * fees.grant);
    limited.limit = fees.grant - 1;
    let report = assess(&inputs(&limited, &fees, &ctl), &thresholds()).unwrap();
    assert_eq!(
        report.warnings,
        vec![OperatingWarning::LimitBelowGrant { limit: fees.grant - 1, grant: fees.grant }]
    );
    limited.limit = fees.grant;
    assert!(assess(&inputs(&limited, &fees, &ctl), &thresholds()).unwrap().warnings.is_empty());

    let funded = state(1_000 * fees.grant, 1_000 * fees.grant);
    let required = funded.funds + funded.floor;
    let mut short = inputs(&funded, &fees, &ctl);
    short.balance = Some(required - 1);
    let report = assess(&short, &thresholds()).unwrap();
    assert_eq!(
        report.warnings,
        vec![OperatingWarning::CapitalBelowReserve { balance: required - 1, required }]
    );
    short.balance = Some(required);
    assert!(assess(&short, &thresholds()).unwrap().warnings.is_empty());

    let mut pending = inputs(&funded, &fees, &ctl);
    pending.relay_pending = true;
    let report = assess(&pending, &thresholds()).unwrap();
    assert_eq!(report.warnings, vec![OperatingWarning::RelayPending]);
    assert!(!report.blocks_next_stake());
}

#[test]
fn degenerate_inputs_are_errors_not_panics() {
    let ctl = controller();
    let zero = RelayFees { control_value: 0, callback_value: 0, grant: 0, funding_processing: 0 };
    let current = state(NANO, NANO);
    assert!(assess(&inputs(&current, &zero, &ctl), &thresholds()).is_err());
    let fees = fees();
    let mut no_interval = inputs(&current, &fees, &ctl);
    no_interval.elections_interval_secs = 0;
    assert!(assess(&no_interval, &thresholds()).is_err());
    let bad = OperatingThresholds { runway_warn_percent: 0, ..thresholds() };
    assert!(assess(&inputs(&current, &fees, &ctl), &bad).is_err());
    assert!(funds_for_runway(&fees, 10, 0).is_err());
}

#[test]
fn funds_for_runway_rounds_up_to_whole_elections() {
    let fees = fees();
    let interval = u64::from(ELECTED_FOR);
    assert_eq!(funds_for_runway(&fees, 0, ELECTED_FOR).unwrap(), 0);
    assert_eq!(funds_for_runway(&fees, 1, ELECTED_FOR).unwrap(), fees.grant);
    assert_eq!(funds_for_runway(&fees, interval, ELECTED_FOR).unwrap(), fees.grant);
    assert_eq!(funds_for_runway(&fees, interval + 1, ELECTED_FOR).unwrap(), 2 * fees.grant);
}

#[test]
fn valid_until_stays_within_the_contract_window() {
    assert_eq!(authorization_valid_until(NOW, 3600).unwrap(), (NOW + 3600) as u32);
    assert!(authorization_valid_until(NOW, 3601).is_err());
    assert!(authorization_valid_until(NOW, 0).is_err());
    assert!(authorization_valid_until(u64::from(u32::MAX), 1).is_err());
}

fn number(value: &str) -> StackEntry {
    StackEntry::Tvm_StackEntryNumber(StackEntryNumber {
        number: Number::Tvm_NumberDecimal(NumberDecimal { number: value.to_string() }),
    })
}

fn address_slice(address: &MsgAddressInt) -> StackEntry {
    let cell = address.write_to_new_cell().unwrap().into_cell().unwrap();
    StackEntry::Tvm_StackEntrySlice(StackEntrySlice {
        slice: tl_slice::Slice { bytes: write_boc(&cell).unwrap() },
    })
}

#[test]
fn operating_state_decodes_the_getter() {
    let stack = TvmStackParser::new(vec![
        number("1329227995784915872903807060280344575"), // 2^120 - 1
        number("5"),
        number("6"),
        number("7"),
        number("1791250000"),
        address_slice(&payer()),
    ]);
    let decoded = OperatingState::decode(&stack).unwrap();
    assert_eq!(decoded.funds, COINS_LIMIT - 1);
    assert_eq!(decoded.allowance, 5);
    assert_eq!(decoded.limit, 6);
    assert_eq!(decoded.floor, 7);
    assert_eq!(decoded.expires, 1_791_250_000);
    assert_eq!(decoded.payer, payer());

    let mut too_big = stack.stack.clone();
    too_big[0] = number("1329227995784915872903807060280344576");
    assert!(OperatingState::decode(&TvmStackParser::new(too_big)).is_err());
    let mut negative = stack.stack.clone();
    negative[1] = number("-1");
    assert!(OperatingState::decode(&TvmStackParser::new(negative)).is_err());
    assert!(OperatingState::decode(&TvmStackParser::new(stack.stack[..5].to_vec())).is_err());
}

#[test]
fn controller_state_decodes_the_authority() {
    let root = BuilderData::new().into_cell().unwrap();
    let stack = TvmStackParser::new(vec![
        number("3"),
        number("18446744073709551615"),
        number("1"),
        number("0x0102030405060708091011121314151617181920212223242526272829303132"),
        StackEntry::Tvm_StackEntryCell(StackEntryCell {
            cell: tl_cell::Cell { bytes: write_boc(&root).unwrap() },
        }),
    ]);
    let authority = ControllerAuthority::decode(&stack).unwrap();
    assert_eq!(authority.epoch, 3);
    assert_eq!(authority.nonce, u64::MAX);
    assert_eq!(authority.algorithm, 1);
    assert_eq!(authority.key_id[0], 0x01);
    assert_eq!(authority.key_id[31], 0x32);
}

#[test]
fn null_cells_are_recognised_in_every_rendering() {
    let cell = BuilderData::new().into_cell().unwrap();
    let stack = TvmStackParser::new(vec![
        StackEntry::Tvm_StackEntryUnsupported,
        StackEntry::Tvm_StackEntryList(StackEntryList {
            list: List::Tvm_List(list::List { elements: vec![] }),
        }),
        number("0"),
        StackEntry::Tvm_StackEntryCell(StackEntryCell {
            cell: tl_cell::Cell { bytes: write_boc(&cell).unwrap() },
        }),
        address_slice(&payer()),
    ]);
    assert!(stack_entry_is_null(&stack, 0).unwrap());
    assert!(stack_entry_is_null(&stack, 1).unwrap());
    assert!(stack_entry_is_null(&stack, 2).unwrap());
    assert!(!stack_entry_is_null(&stack, 3).unwrap());
    assert!(stack_entry_is_null(&stack, 4).is_err());
    assert!(stack_entry_is_null(&stack, 5).is_err());
}
