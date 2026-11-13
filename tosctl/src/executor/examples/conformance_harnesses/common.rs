// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: GPL-3.0-only
//! Context decoding shared by the harnesses, and the canonical text of stack values
//! (test/conformance/ref/common.cpp, `stack_entry_text`).
use chain_block::{base64_decode, read_single_root_boc, Cell, CellType, SliceData};
use serde_json::{json, Map, Value};
use tos_vm::stack::{
    continuation::{ContinuationData, ContinuationType},
    integer::IntegerData,
    savelist::SaveList,
    Stack, StackItem,
};

pub type Object = Map<String, Value>;

/// Nesting and length bounds of input stack values, as in the reference.
const MAX_ITEM_DEPTH: usize = 32;
pub const MAX_ITEMS: usize = 255;
/// Decimal integers of the stack item schema.
const MAX_INT_DIGITS: usize = 80;

pub fn harness_error(message: &str) -> Value {
    json!({ "harness_error": message })
}

/// Every key present must be allowed and every required key present.
pub fn check_keys(
    object: &Object,
    required: &[&str],
    allowed: &[&str],
    what: &str,
) -> anyhow::Result<()> {
    for key in required {
        anyhow::ensure!(object.contains_key(*key), "{what}: missing field {key}");
    }
    for key in object.keys() {
        anyhow::ensure!(allowed.contains(&key.as_str()), "{what}: unsupported field {key}");
    }
    Ok(())
}

/// An integer field within `min..=max`; `None` when absent.
pub fn integer(object: &Object, key: &str, min: i64, max: i64) -> anyhow::Result<Option<i64>> {
    let Some(value) = object.get(key) else {
        return Ok(None);
    };
    let number = value.as_i64().ok_or_else(|| anyhow::anyhow!("{key} must be a 64-bit integer"))?;
    anyhow::ensure!((min..=max).contains(&number), "{key} must be within {min}..{max}");
    Ok(Some(number))
}

pub fn required_integer(object: &Object, key: &str, min: i64, max: i64) -> anyhow::Result<i64> {
    integer(object, key, min, max)?.ok_or_else(|| anyhow::anyhow!("missing field {key}"))
}

pub fn text<'a>(object: &'a Object, key: &str) -> anyhow::Result<Option<&'a str>> {
    match object.get(key) {
        None => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.as_str())),
        Some(_) => anyhow::bail!("{key} must be a string"),
    }
}

/// A single-root BOC in standard base64.
pub fn boc(value: &Value, what: &str) -> anyhow::Result<Cell> {
    let text = value.as_str().ok_or_else(|| anyhow::anyhow!("{what} must be a base64 BOC"))?;
    let bytes = base64_decode(text).map_err(|e| anyhow::anyhow!("{what}: {e}"))?;
    read_single_root_boc(bytes).map_err(|e| anyhow::anyhow!("{what}: {e}"))
}

pub fn optional_boc(object: &Object, key: &str) -> anyhow::Result<Option<Cell>> {
    object.get(key).map(|value| boc(value, key)).transpose()
}

pub fn required_boc(object: &Object, key: &str) -> anyhow::Result<Cell> {
    optional_boc(object, key)?.ok_or_else(|| anyhow::anyhow!("missing field {key}"))
}

/// The reference loads code and slice values outside the VM, where an exotic cell (library,
/// pruned branch, Merkle proof or update) cannot be loaded and the context is refused.
pub fn ordinary_slice(cell: Cell, what: &str) -> anyhow::Result<SliceData> {
    anyhow::ensure!(
        cell.cell_type() == CellType::Ordinary,
        "{what}: an exotic cell cannot be loaded as a slice"
    );
    SliceData::load_cell(cell).map_err(|e| anyhow::anyhow!("{what}: {e}"))
}

fn decimal(text: &str) -> anyhow::Result<IntegerData> {
    let digits = text.strip_prefix('-').unwrap_or(text);
    anyhow::ensure!(
        !digits.is_empty()
            && digits.len() <= MAX_INT_DIGITS
            && digits.bytes().all(|b| b.is_ascii_digit()),
        "invalid integer stack item"
    );
    // Values outside the signed 257-bit range are refused by the conversion.
    text.parse::<IntegerData>().map_err(|_| anyhow::anyhow!("invalid integer stack item"))
}

/// Input stack value of schema/common-v1.schema.json.
pub fn stack_item(value: &Value, depth: usize) -> anyhow::Result<StackItem> {
    anyhow::ensure!(depth <= MAX_ITEM_DEPTH, "stack item nesting too deep");
    let object =
        value.as_object().ok_or_else(|| anyhow::anyhow!("stack item must be an object"))?;
    let kind = text(object, "type")?.ok_or_else(|| anyhow::anyhow!("stack item without a type"))?;
    match kind {
        "null" => {
            check_keys(object, &["type"], &["type"], "null item")?;
            Ok(StackItem::None)
        }
        "nan" => {
            check_keys(object, &["type"], &["type"], "nan item")?;
            Ok(StackItem::int(IntegerData::nan()))
        }
        "int" => {
            check_keys(object, &["type", "value"], &["type", "value"], "int item")?;
            let value = text(object, "value")?.ok_or_else(|| anyhow::anyhow!("int item value"))?;
            Ok(StackItem::int(decimal(value)?))
        }
        "cell" => {
            check_keys(object, &["type", "boc"], &["type", "boc"], "cell item")?;
            Ok(StackItem::cell(required_boc(object, "boc")?))
        }
        "slice" => {
            check_keys(object, &["type", "boc"], &["type", "boc"], "slice item")?;
            Ok(StackItem::slice(ordinary_slice(required_boc(object, "boc")?, "slice item")?))
        }
        "tuple" => {
            check_keys(object, &["type", "items"], &["type", "items"], "tuple item")?;
            let items = object
                .get("items")
                .and_then(Value::as_array)
                .ok_or_else(|| anyhow::anyhow!("tuple items must be an array"))?;
            anyhow::ensure!(items.len() <= MAX_ITEMS, "tuple too long");
            let next = depth.saturating_add(1);
            let items = items
                .iter()
                .map(|item| stack_item(item, next))
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(StackItem::tuple(items))
        }
        other => anyhow::bail!("unknown stack item type {other}"),
    }
}

fn slice_text(s: &SliceData) -> anyhow::Result<String> {
    let refs = s.get_references();
    Ok(format!(
        "{:X}:{}-{}:{}-{}",
        s.cell()?.repr_hash(),
        s.pos(),
        s.pos().saturating_add(s.remaining_bits()),
        refs.start,
        refs.end
    ))
}

fn savelist(save: &SaveList) -> String {
    let out: String = [0, 1, 2, 3, 4, 5, 7]
        .iter()
        .filter(|&&i| save.get(i).is_some())
        .map(|i| format!("c{i}"))
        .collect();
    if out.is_empty() {
        "none".to_string()
    } else {
        out
    }
}

/// Named as the C++ VM names its continuation classes. As there, only ordinary continuations and
/// envelopes carry control data; the code a continuation carries is not part of the text.
fn continuation_text(
    cont: &ContinuationData,
    depth: usize,
    budget: &mut usize,
) -> anyhow::Result<String> {
    let name = match &cont.type_of {
        ContinuationType::Ordinary => "vmc_std",
        ContinuationType::Envelope(_) => "vmc_envelope",
        ContinuationType::Quit(_) => "vmc_quit",
        ContinuationType::ExcQuit => "vmc_quit_exc",
        ContinuationType::PushInt(..) => "vmc_pushint",
        ContinuationType::Repeat { .. } => "vmc_repeat",
        ContinuationType::Again { .. } => "vmc_again",
        ContinuationType::Until { .. } => "vmc_until",
        ContinuationType::While { check_cond: true, .. } => "vmc_while_cond",
        ContinuationType::While { check_cond: false, .. } => "vmc_while_body",
    };
    if !cont.has_control_data() {
        return Ok(format!("cont:{name}"));
    }
    Ok(format!(
        "cont:{name}:nargs={}:save={}:stack=[{}]",
        cont.nargs,
        savelist(&cont.savelist),
        items_text(&cont.stack, depth, budget)?.join(" ")
    ))
}

/// Output values nest without a bound in the VM itself; the text is refused past this depth
/// instead of recursing without limit.
const MAX_TEXT_DEPTH: usize = 512;

/// Values are shared, so a shallow result can still expand without limit; one rendering (a final
/// stack) visits at most this many values, each counted every time it is visited, as in C++.
const MAX_TEXT_VALUES: usize = 1 << 20;

fn entry_text(item: &StackItem, depth: usize, budget: &mut usize) -> anyhow::Result<String> {
    anyhow::ensure!(depth <= MAX_TEXT_DEPTH, "final stack value nested too deep");
    anyhow::ensure!(*budget > 0, "final stack value too large");
    *budget = budget.saturating_sub(1);
    let next = depth.saturating_add(1);
    Ok(match item {
        StackItem::None => "null".to_string(),
        StackItem::Integer(x) => x.to_str(),
        StackItem::Cell(cell) => format!("cell:{:X}", cell.repr_hash()),
        StackItem::Slice(s) => format!("slice:{}", slice_text(s)?),
        StackItem::Builder(b) => format!(
            "builder:{}:{}:{:X}",
            b.length_in_bits(),
            b.references().len(),
            b.as_ref().clone().into_cell()?.repr_hash()
        ),
        StackItem::Continuation(cont) => continuation_text(cont, next, budget)?,
        StackItem::Tuple(items) => {
            let items = items
                .iter()
                .map(|item| entry_text(item, next, budget))
                .collect::<anyhow::Result<Vec<_>>>()?;
            format!("({})", items.join(" "))
        }
    })
}

/// Canonical texts, bottom of the stack first.
pub fn stack_items_text(stack: &Stack, depth: usize) -> anyhow::Result<Vec<String>> {
    let mut budget = MAX_TEXT_VALUES;
    items_text(stack, depth, &mut budget)
}

fn items_text(stack: &Stack, depth: usize, budget: &mut usize) -> anyhow::Result<Vec<String>> {
    stack.iter().map(|item| entry_text(item, depth, budget)).collect()
}
