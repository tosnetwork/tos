/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 */
//! Reading the configuration contract's proposals without a recursion that an
//! answer can drive past the stack.
//!
//! `list_proposals` and `get_proposal` return cons lists, which the node serves as
//! nested JSON whose depth grows with the number of proposals and voters. The JSON
//! parser recurses once per level; the conversion into stack entries and every
//! drop here are iterative. All of it happens on a dedicated worker thread whose
//! stack is sized for the depth limit, behind a depth preflight that enforces that
//! limit, and only flat results (`ConfigProposal`s, an expiry, or a bounded error
//! string) come back. Other getters keep the ordinary path.
//!
//! The answer is read at one masterchain checkpoint taken before the getter runs.
//! When the `list_proposals` answer exceeds the transport limit, or the getter
//! returns exit 13 at that checkpoint, the list is read instead from the contract's
//! stored vote dictionary at the same checkpoint and address, after its code is
//! checked to be the one whose layout this crate decodes. No other failure falls
//! back, and `get_proposal` never does. Neither representation is unbounded: a
//! vote dictionary too large for both is an explicit error naming both limits,
//! never a partial list.

use super::{
    ConfigProposal, ProposalHash, decode_proposal, decode_proposal_expiry, decode_proposal_list,
    proposal_state,
};
use crate::chain_provider::{MasterchainCheckpoint, validate_masterchain_checkpoint};
use base64::Engine;
use chain_block::MsgAddressInt;
use chain_rpc_client::v2::{
    RPCStackEntry,
    client_json_rpc::{ClientJsonRpc, RawAttempt, RawRpcResponse},
    data_models::{BlockIdExt, RunGetMethodParams},
};
use common::tvm_stack_parser::TvmStackParser;
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use std::sync::{
    Arc, OnceLock,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tl_api::tos::tvm::{
    List, Number, StackEntry, Tuple, cell::Cell as TvmCell, list, numberdecimal::NumberDecimal,
    slice::Slice as TvmSlice, stackentry, tuple,
};

/// What to read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProposalRead {
    /// Every proposal `list_proposals` returns.
    List,
    /// One proposal, through `get_proposal`.
    One(ProposalHash),
    /// Only the expiry of one proposal, through `get_proposal`.
    Expiry(ProposalHash),
}

/// The flat result of a [`ProposalRead`].
#[derive(Clone)]
pub enum ProposalAnswer {
    List(Vec<ConfigProposal>),
    One(Option<ConfigProposal>),
    Expiry(Option<u32>),
}

/// The transport's limit on one response body.
pub const MAX_RESPONSE_BYTES: usize = chain_rpc_client::v2::MAX_RESPONSE_BYTES;

/// The fewest bytes the node spends on one level of a voter cons cell: a two-element
/// tuple wrapper with its separating comma, holding a one-digit number. Three JSON
/// levels each. Pinned against the node's own bytes in the tests.
pub const MIN_CONS_CELL_BYTES: usize = 76;
pub const MIN_NUMBER_BYTES: usize = 84;
pub const MIN_VOTER_LEVEL_BYTES: usize = MIN_CONS_CELL_BYTES + MIN_NUMBER_BYTES;

/// JSON nesting of everything around the deepest cons chain: the envelope, the
/// result, the stack, the pair and the proposal tuple. Pinned in the tests at less
/// than half of this.
pub const FIXED_NESTING_ALLOWANCE: usize = 64;

/// The deepest JSON this path parses. A decodable answer within the byte limit
/// cannot reach it: the cheapest nesting per byte any answer can buy is a voter cons
/// cell, three levels for [`MIN_VOTER_LEVEL_BYTES`]. Anything deeper is refused by
/// the preflight before a recursive parser sees it.
pub const MAX_JSON_DEPTH: usize =
    3 * MAX_RESPONSE_BYTES.div_ceil(MIN_VOTER_LEVEL_BYTES) + FIXED_NESTING_ALLOWANCE;

/// Proposal reads that may run at once, each on its own worker.
pub const WORKERS: usize = 2;

/// Each worker's stack. serde_json recurses once per JSON level, so the parse at
/// [`MAX_JSON_DEPTH`] sets the size. The whole pipeline (parse, conversion,
/// decoding, destruction, malformed and partial answers included) was measured at
/// 5.9 MiB in release and 34.6 MiB in debug builds (`measure_worker_stack` in
/// `tests/proposal_read_workers.rs`), and must stay within a quarter of this. Both
/// profiles keep the same byte and depth limits; only the reservation differs. It is
/// virtual: pages are committed only as they are touched.
#[cfg(not(debug_assertions))]
pub const WORKER_STACK_BYTES: usize = 128 << 20;
#[cfg(debug_assertions)]
pub const WORKER_STACK_BYTES: usize = 256 << 20;

/// How long a read waits for a worker before it is refused as busy.
pub const ADMISSION_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest error text that crosses back from a worker.
const MAX_ERROR_CHARS: usize = 512;

fn bounded(text: impl AsRef<str>) -> String {
    text.as_ref().chars().take(MAX_ERROR_CHARS).collect()
}

// ─── Depth preflight ──────────────────────────────────────────────────────────

/// Why the preflight refused a body.
#[derive(Debug, PartialEq, Eq)]
pub enum PreflightError {
    /// An opening bracket at `at` would exceed `limit` levels.
    TooDeep { at: usize, limit: usize },
    /// A closing bracket at `at` has nothing open to close.
    Underflow { at: usize },
}

impl std::fmt::Display for PreflightError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PreflightError::TooDeep { at, limit } => {
                write!(f, "the response nests deeper than {limit} levels (at byte {at})")
            }
            PreflightError::Underflow { at } => {
                write!(f, "the response closes more than it opens (at byte {at})")
            }
        }
    }
}

/// Bounds the nesting a recursive JSON parser will meet. It is not a validator:
/// it only counts brackets outside strings, so syntax, escapes, UTF-8, delimiter
/// kinds and trailing content are left to the parser that runs after it.
///
/// A quote ends a string unless an odd run of backslashes precedes it. Inside a
/// string nothing is structural, `\uXXXX` included, since the escape's hex digits
/// are never brackets themselves and the character it encodes is not a delimiter.
pub fn depth_preflight(text: &[u8], limit: usize) -> Result<(), PreflightError> {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut backslashes = 0usize;
    for (at, byte) in text.iter().enumerate() {
        if in_string {
            match byte {
                b'\\' => backslashes = backslashes.saturating_add(1),
                b'"' => {
                    if backslashes.is_multiple_of(2) {
                        in_string = false;
                    }
                    backslashes = 0;
                }
                _ => backslashes = 0,
            }
            continue;
        }
        match byte {
            b'"' => {
                in_string = true;
                backslashes = 0;
            }
            b'{' | b'[' => {
                if depth >= limit {
                    return Err(PreflightError::TooDeep { at, limit });
                }
                depth = depth.saturating_add(1);
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1).ok_or(PreflightError::Underflow { at })?;
            }
            _ => {}
        }
    }
    Ok(())
}

// ─── Strict JSON ──────────────────────────────────────────────────────────────

/// A JSON document that refuses duplicate keys. It is parsed on a worker whose
/// stack is sized for the depth limit; dropping it dismantles it level by level.
#[derive(Debug)]
enum Json {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Drop for Json {
    fn drop(&mut self) {
        let mut pending: Vec<Json> = match self {
            Json::Array(items) if !items.is_empty() => std::mem::take(items),
            Json::Object(fields) if !fields.is_empty() => {
                std::mem::take(fields).into_iter().map(|(_, value)| value).collect()
            }
            _ => return,
        };
        while let Some(mut next) = pending.pop() {
            match &mut next {
                Json::Array(items) => pending.append(items),
                Json::Object(fields) => pending.extend(fields.drain(..).map(|(_, value)| value)),
                _ => {}
            }
            // `next` now holds no children, so its own drop returns at once.
        }
    }
}

impl Json {
    fn kind(&self) -> &'static str {
        match self {
            Json::Null => "null",
            Json::Bool(_) => "a boolean",
            Json::Number(_) => "a number",
            Json::String(_) => "a string",
            Json::Array(_) => "an array",
            Json::Object(_) => "an object",
        }
    }

    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(fields) => {
                fields.iter().find(|(name, _)| name == key).map(|(_, value)| value)
            }
            _ => None,
        }
    }

    fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(text) => Some(text),
            _ => None,
        }
    }

    /// Moves the value of `key` out of an object.
    fn take(&mut self, key: &str) -> Option<Json> {
        match self {
            Json::Object(fields) => {
                let position = fields.iter().position(|(name, _)| name == key)?;
                Some(fields.swap_remove(position).1)
            }
            _ => None,
        }
    }

    /// Moves the items out of an array.
    fn take_items(&mut self) -> Option<Vec<Json>> {
        match self {
            Json::Array(items) => Some(std::mem::take(items)),
            _ => None,
        }
    }
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Json;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Json, E> {
        Ok(Json::Bool(value))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Json, E> {
        Ok(Json::Number(value.into()))
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Json, E> {
        Ok(Json::Number(value.into()))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Json, E> {
        serde_json::Number::from_f64(value)
            .map(Json::Number)
            .ok_or_else(|| E::custom("a non-finite number"))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Json, E> {
        Ok(Json::String(value.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Json, E> {
        Ok(Json::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Json, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element::<Json>()? {
            items.push(item);
        }
        Ok(Json::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Json, A::Error> {
        let mut fields: Vec<(String, Json)> = Vec::new();
        // An ordered set, so a wide object costs n log n to check, with no hash an
        // answer could steer.
        let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!("duplicate key {:?}", bounded(&key))));
            }
            let value = map.next_value::<Json>()?;
            fields.push((key, value));
        }
        Ok(Json::Object(fields))
    }
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Json, D::Error> {
        deserializer.deserialize_any(JsonVisitor)
    }
}

/// Parses one whole response: the depth preflight first, so no document deeper
/// than [`MAX_JSON_DEPTH`] reaches the parser; then serde_json with its own
/// recursion limit lifted (the preflight is the bound, and the worker's stack is
/// sized for it), refusing duplicate keys; then a check that nothing follows the
/// document. Every partial tree an error abandons is a [`Json`], whose drop does
/// not recurse.
fn parse_document(text: &str) -> Result<Json, String> {
    depth_preflight(text.as_bytes(), MAX_JSON_DEPTH).map_err(|error| error.to_string())?;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    deserializer.disable_recursion_limit();
    let document = Json::deserialize(&mut deserializer)
        .map_err(|error| bounded(format!("malformed JSON response: {error}")))?;
    deserializer.end().map_err(|error| bounded(format!("malformed JSON response: {error}")))?;
    Ok(document)
}

/// The `result` of a JSON-RPC envelope, under the client's envelope rules: version
/// 2.0, the request's own id, a boolean `ok`, and exactly one of `result` or an
/// `error` with its `code`. An error envelope becomes a bounded error string.
fn envelope_result(mut document: Json, status: u16, expected_id: &str) -> Result<Json, String> {
    if !matches!(document, Json::Object(_)) {
        return Err(format!("the response is {}, not an object", document.kind()));
    }
    if document.get("jsonrpc").and_then(Json::as_str) != Some("2.0") {
        return Err("jsonrpc must be exactly 2.0".to_string());
    }
    match document.get("id") {
        Some(Json::String(id)) if id == expected_id => {}
        Some(_) => return Err("response id does not match the request".to_string()),
        None => return Err("response has no id".to_string()),
    }
    let ok = match document.get("ok") {
        Some(Json::Bool(ok)) => *ok,
        _ => return Err("ok must be a boolean".to_string()),
    };
    let has_result = document.has("result");
    let has_error = document.has("error") || document.has("code");
    if ok {
        if !has_result || has_error {
            return Err("successful response must contain result and no error fields".into());
        }
        if !(200..300).contains(&status) {
            return Err(format!("HTTP status {status} on a successful envelope"));
        }
        return document.take("result").ok_or_else(|| "response has no result".to_string());
    }
    if has_result || !document.has("error") || !document.has("code") {
        return Err("error response must contain error and code and no result".to_string());
    }
    let code = match document.get("code") {
        Some(Json::Number(code)) => code
            .as_u64()
            .and_then(|code| u32::try_from(code).ok())
            .ok_or_else(|| "error code must be an unsigned 32-bit integer".to_string())?,
        _ => return Err("error code must be an unsigned 32-bit integer".to_string()),
    };
    let message = document
        .get("error")
        .and_then(Json::as_str)
        .ok_or_else(|| "error must be a string".to_string())?;
    Err(bounded(format!("the endpoint answered error {code}: {message}")))
}

fn block_id(value: &Json) -> Result<BlockIdExt, String> {
    let text = |key: &str| {
        value.get(key).and_then(Json::as_str).ok_or_else(|| format!("block id has no {key}"))
    };
    let integer = |key: &str| match value.get(key) {
        Some(Json::Number(number)) => {
            number.as_i64().ok_or_else(|| format!("block id {key} is not an integer"))
        }
        _ => Err(format!("block id has no {key}")),
    };
    let hash = |key: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(text(key)?)
            .map_err(|_| format!("block id {key} is not base64"))
    };
    Ok(BlockIdExt {
        r#type: text("@type")?.to_string(),
        workchain: i32::try_from(integer("workchain")?)
            .map_err(|_| "block id workchain exceeds int32".to_string())?,
        shard: text("shard")?.parse::<i64>().map_err(|_| "block id shard is not int64")?,
        seqno: u32::try_from(integer("seqno")?)
            .map_err(|_| "block id seqno exceeds uint32".to_string())?,
        root_hash: hash("root_hash")?,
        file_hash: hash("file_hash")?,
    })
}

fn checked_block(result: &Json, checkpoint: &MasterchainCheckpoint) -> Result<(), String> {
    let block = block_id(result.get("block_id").ok_or("the answer names no block")?)?;
    validate_masterchain_checkpoint(&block, checkpoint)
        .map_err(|_| "the answer was read at another block than the checkpoint".to_string())
}

// ─── Stack conversion ─────────────────────────────────────────────────────────

enum Converted {
    Leaf(StackEntry),
    Tuple(Vec<Json>),
    List(Vec<Json>),
}

fn bytes_field(entry: &mut Json, outer: &str) -> Result<Vec<u8>, String> {
    let inner = entry.take(outer).ok_or_else(|| format!("stack {outer} has no payload"))?;
    let encoded = inner.get("bytes").and_then(Json::as_str).ok_or("stack payload has no bytes")?;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| format!("stack {outer} bytes are not base64"))
}

fn elements(entry: &mut Json, outer: &str) -> Result<Vec<Json>, String> {
    let mut inner = entry.take(outer).ok_or_else(|| format!("stack {outer} has no payload"))?;
    inner
        .take("elements")
        .and_then(|mut elements| elements.take_items())
        .ok_or_else(|| format!("stack {outer} has no elements array"))
}

/// One served stack entry, consumed. Its children are handed back unconverted, so
/// the conversion below never recurses.
fn convert_one(mut entry: Json) -> Result<Converted, String> {
    let kind = entry.get("@type").and_then(Json::as_str).ok_or("stack entry has no @type")?;
    match kind {
        "tvm.stackEntryNumber" => {
            let number = entry
                .get("number")
                .and_then(|number| number.get("number"))
                .and_then(Json::as_str)
                .ok_or("stack number has no decimal text")?;
            Ok(Converted::Leaf(StackEntry::Tvm_StackEntryNumber(stackentry::StackEntryNumber {
                number: Number::Tvm_NumberDecimal(NumberDecimal { number: number.to_string() }),
            })))
        }
        "tvm.stackEntryCell" => {
            let bytes = bytes_field(&mut entry, "cell")?;
            Ok(Converted::Leaf(StackEntry::Tvm_StackEntryCell(stackentry::StackEntryCell {
                cell: TvmCell { bytes },
            })))
        }
        "tvm.stackEntrySlice" => {
            let bytes = bytes_field(&mut entry, "slice")?;
            Ok(Converted::Leaf(StackEntry::Tvm_StackEntrySlice(stackentry::StackEntrySlice {
                slice: TvmSlice { bytes },
            })))
        }
        "tvm.stackEntryUnsupported" => Ok(Converted::Leaf(StackEntry::Tvm_StackEntryUnsupported)),
        "tvm.stackEntryTuple" => Ok(Converted::Tuple(elements(&mut entry, "tuple")?)),
        "tvm.stackEntryList" => Ok(Converted::List(elements(&mut entry, "list")?)),
        other => Err(bounded(format!("unknown stack entry type {other:?}"))),
    }
}

/// Drops a stack level by level. A served stack can nest as deep as the depth limit
/// allows, and the generated stack types drop recursively.
fn dismantle(entries: Vec<StackEntry>) {
    let mut pending = entries;
    while let Some(mut entry) = pending.pop() {
        match &mut entry {
            StackEntry::Tvm_StackEntryTuple(served) => {
                let Tuple::Tvm_Tuple(inner) = &mut served.tuple;
                pending.append(&mut inner.elements);
            }
            StackEntry::Tvm_StackEntryList(served) => {
                let List::Tvm_List(inner) = &mut served.list;
                pending.append(&mut inner.elements);
            }
            _ => {}
        }
    }
}

enum OpenKind {
    Root,
    Tuple,
    List,
}

struct OpenEntry {
    kind: OpenKind,
    pending: std::vec::IntoIter<Json>,
    built: Vec<StackEntry>,
}

/// Converts served stack entries into the stack decoders read, without recursion:
/// an explicit stack of open containers replaces the call stack, and every JSON
/// node is moved out of its parent and dropped flat as it is converted. On an error
/// everything built so far is dismantled the same way.
fn convert_stack(entries: Vec<Json>) -> Result<Vec<StackEntry>, String> {
    let mut open =
        vec![OpenEntry { kind: OpenKind::Root, pending: entries.into_iter(), built: Vec::new() }];
    let converted = convert_open(&mut open);
    for frame in open {
        dismantle(frame.built);
    }
    converted
}

fn convert_open(open: &mut Vec<OpenEntry>) -> Result<Vec<StackEntry>, String> {
    loop {
        let top = open.last_mut().ok_or("stack conversion lost its root")?;
        match top.pending.next() {
            Some(entry) => match convert_one(entry)? {
                Converted::Leaf(leaf) => top.built.push(leaf),
                Converted::Tuple(children) => open.push(OpenEntry {
                    kind: OpenKind::Tuple,
                    built: Vec::with_capacity(children.len()),
                    pending: children.into_iter(),
                }),
                Converted::List(children) => open.push(OpenEntry {
                    kind: OpenKind::List,
                    built: Vec::with_capacity(children.len()),
                    pending: children.into_iter(),
                }),
            },
            None => {
                let mut done = open.pop().ok_or("stack conversion lost its root")?;
                let built = std::mem::take(&mut done.built);
                let entry = match done.kind {
                    OpenKind::Root => return Ok(built),
                    OpenKind::Tuple => {
                        StackEntry::Tvm_StackEntryTuple(stackentry::StackEntryTuple {
                            tuple: Tuple::Tvm_Tuple(tuple::Tuple { elements: built }),
                        })
                    }
                    OpenKind::List => StackEntry::Tvm_StackEntryList(stackentry::StackEntryList {
                        list: List::Tvm_List(list::List { elements: built }),
                    }),
                };
                open.last_mut().ok_or("stack conversion lost its root")?.built.push(entry);
            }
        }
    }
}

// ─── Decoding on the worker ───────────────────────────────────────────────────

/// How one endpoint's answer ended. Flat: only this crosses back from a worker.
enum Attempt<T> {
    /// A valid envelope at the checkpoint, decoded.
    Answer(T),
    /// A valid envelope at the checkpoint whose `list_proposals` exited with 13,
    /// which it does when its dictionary walk outgrows the node's get-method gas.
    Exit13,
    /// A valid envelope at the checkpoint that is refused: any other non-zero exit,
    /// a result or stack the strict decoder refuses, or unsupported code. Terminal:
    /// another endpoint is not asked.
    Refused(String),
    /// A failure of this endpoint's answer as a JSON-RPC answer about the
    /// checkpoint: malformed or over-deep JSON, an envelope that breaks the
    /// client's rules (an error envelope included), or an answer read at another
    /// block or naming none. The next endpoint is asked.
    Retry(&'static str),
}

impl<T> std::fmt::Debug for Attempt<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Attempt::Answer(_) => f.write_str("Answer"),
            Attempt::Exit13 => f.write_str("Exit13"),
            Attempt::Refused(reason) => write!(f, "Refused({reason:?})"),
            Attempt::Retry(category) => write!(f, "Retry({category})"),
        }
    }
}

/// The envelope and block layer every answer passes before its content is read.
/// Retryable failures only.
fn checked_result(
    response: &RawRpcResponse,
    checkpoint: &MasterchainCheckpoint,
) -> Result<Json, &'static str> {
    if depth_preflight(response.text.as_bytes(), MAX_JSON_DEPTH).is_err() {
        return Err("too_deep");
    }
    let document = parse_document(&response.text).map_err(|_| "malformed_json")?;
    let result = envelope_result(document, response.status, &response.request_id)
        .map_err(|_| "envelope_error")?;
    // The block before anything the answer says: an answer from another block, or
    // naming none, is no answer about the checkpoint.
    checked_block(&result, checkpoint).map_err(|_| "wrong_block")?;
    Ok(result)
}

/// Classifies one getter answer. Runs on a worker.
fn decode_getter_response(
    response: &RawRpcResponse,
    read: ProposalRead,
    checkpoint: &MasterchainCheckpoint,
) -> Attempt<ProposalAnswer> {
    let mut result = match checked_result(response, checkpoint) {
        Ok(result) => result,
        Err(category) => return Attempt::Retry(category),
    };
    match result.get("exit_code") {
        Some(Json::Number(code)) if code.as_i64() == Some(0) => {}
        Some(Json::Number(code)) if code.as_i64() == Some(13) && read == ProposalRead::List => {
            return Attempt::Exit13;
        }
        Some(Json::Number(code)) => {
            return Attempt::Refused(format!("the getter exited with code {code}"));
        }
        _ => return Attempt::Refused("the answer has no exit code".to_string()),
    }
    let Some(served) = result.take("stack").and_then(|mut stack| stack.take_items()) else {
        return Attempt::Refused("the answer has no stack".to_string());
    };
    drop(result);
    // The node serializes the stack top first; decoders read it in return order.
    let mut entries = match convert_stack(served) {
        Ok(entries) => entries,
        Err(error) => return Attempt::Refused(error),
    };
    entries.reverse();
    let mut stack = TvmStackParser::new(entries);
    let answer = match read {
        ProposalRead::List => decode_proposal_list(&stack).map(ProposalAnswer::List),
        ProposalRead::One(hash) => decode_proposal(hash, &stack).map(ProposalAnswer::One),
        ProposalRead::Expiry(_) => decode_proposal_expiry(&stack).map(ProposalAnswer::Expiry),
    };
    dismantle(std::mem::take(&mut stack.stack));
    match answer {
        Ok(answer) => Attempt::Answer(answer),
        Err(error) => Attempt::Refused(bounded(format!("{error:#}"))),
    }
}

/// Classifies one answer for the contract's account at the checkpoint. Runs on a
/// worker.
fn decode_account_response(
    response: &RawRpcResponse,
    read: ProposalRead,
    checkpoint: &MasterchainCheckpoint,
) -> Attempt<ProposalAnswer> {
    let result = match checked_result(response, checkpoint) {
        Ok(result) => result,
        Err(category) => return Attempt::Retry(category),
    };
    if result.get("state").and_then(Json::as_str) != Some("active") {
        return Attempt::Refused(
            "the configuration contract is not active at the checkpoint".to_string(),
        );
    }
    let boc = |key: &str| {
        let encoded = result
            .get(key)
            .and_then(Json::as_str)
            .ok_or_else(|| format!("the account has no {key}"))?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(|_| format!("the account {key} is not base64"))
    };
    let (code, data) = match (boc("code"), boc("data")) {
        (Ok(code), Ok(data)) => (code, data),
        (Err(error), _) | (_, Err(error)) => return Attempt::Refused(error),
    };
    match proposal_state::decode_state(&code, &data, read) {
        Ok(answer) => Attempt::Answer(answer),
        Err(error) => Attempt::Refused(bounded(format!("{error:#}"))),
    }
}

// ─── Workers and admission ────────────────────────────────────────────────────

/// Bounds how many workers exist at once. A permit is taken before a response is
/// buffered and moves into the worker, so it is released only when the worker
/// actually ends, never when the waiting future is dropped.
pub struct Admission {
    permits: Arc<tokio::sync::Semaphore>,
    timeout: Duration,
    stack_bytes: usize,
    live: Arc<AtomicUsize>,
    most_live: Arc<AtomicUsize>,
}

struct LiveWorker(Arc<AtomicUsize>);

impl LiveWorker {
    fn enter(live: Arc<AtomicUsize>, most_live: &AtomicUsize) -> Self {
        let now = live.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        most_live.fetch_max(now, Ordering::SeqCst);
        LiveWorker(live)
    }
}

impl Drop for LiveWorker {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Admission {
    pub fn new(workers: usize, timeout: Duration, stack_bytes: usize) -> Self {
        Self {
            permits: Arc::new(tokio::sync::Semaphore::new(workers)),
            timeout,
            stack_bytes,
            live: Arc::new(AtomicUsize::new(0)),
            most_live: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Permits no read holds right now.
    pub fn idle_permits(&self) -> usize {
        self.permits.available_permits()
    }

    /// Workers alive now under this admission, and the most ever alive at once.
    pub fn worker_counts(&self) -> (usize, usize) {
        (self.live.load(Ordering::SeqCst), self.most_live.load(Ordering::SeqCst))
    }

    /// The process-wide admission every production read goes through.
    pub fn global() -> &'static Admission {
        static GLOBAL: OnceLock<Admission> = OnceLock::new();
        GLOBAL.get_or_init(|| Admission::new(WORKERS, ADMISSION_TIMEOUT, WORKER_STACK_BYTES))
    }

    async fn admit(&self) -> anyhow::Result<tokio::sync::OwnedSemaphorePermit> {
        match tokio::time::timeout(self.timeout, self.permits.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => anyhow::bail!("proposal read admission is closed"),
            Err(_) => anyhow::bail!(
                "proposal reads are busy: no worker became free within {} s",
                self.timeout.as_secs()
            ),
        }
    }

    /// Runs `job` on a new worker that holds `permit` while it runs, and hands the
    /// permit back with the flat result, so one read's attempts reuse one permit
    /// and never overlap. If the caller goes away, the permit stays with the worker
    /// until the job ends. A panic is reduced to a message on the worker.
    async fn on_worker<T, F>(
        &self,
        permit: tokio::sync::OwnedSemaphorePermit,
        job: F,
    ) -> anyhow::Result<(T, tokio::sync::OwnedSemaphorePermit)>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
    {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        let live = self.live.clone();
        let most_live = self.most_live.clone();
        std::thread::Builder::new()
            .name("proposal-read".to_string())
            .stack_size(self.stack_bytes)
            .spawn(move || {
                let live = LiveWorker::enter(live, &most_live);
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job))
                    .map(|value| (value, permit))
                    .map_err(|_| "the proposal read worker panicked".to_string());
                drop(live);
                // A dropped receiver means the caller went away: the result and the
                // permit are dropped here, after the work has ended.
                let _ = sender.send(outcome);
            })
            .map_err(|error| anyhow::anyhow!("cannot start a proposal read worker: {error}"))?;
        receiver
            .await
            .map_err(|_| anyhow::anyhow!("the proposal read worker ended without a result"))?
            .map_err(anyhow::Error::msg)
    }
}

fn read_label(read: ProposalRead) -> &'static str {
    match read {
        ProposalRead::List => "list_proposals",
        ProposalRead::One(_) | ProposalRead::Expiry(_) => "get_proposal",
    }
}

fn getter_params(
    address: &MsgAddressInt,
    read: ProposalRead,
    checkpoint: &MasterchainCheckpoint,
) -> RunGetMethodParams {
    let stack = match read {
        ProposalRead::List => vec![],
        ProposalRead::One(hash) | ProposalRead::Expiry(hash) => {
            vec![RPCStackEntry::from(crate::stack_utils::bytes_to_stack_entry(&hash))]
        }
    };
    RunGetMethodParams {
        address: address.to_string(),
        method_id: read_label(read).to_string(),
        stack: Some(stack),
        seqno: Some(checkpoint.seqno),
    }
}

/// The current masterchain block, as the checkpoint every read of one request is
/// pinned to.
async fn checkpoint(client: &ClientJsonRpc) -> anyhow::Result<MasterchainCheckpoint> {
    let info = client.get_masterchain_info().await?;
    anyhow::ensure!(info.last.workchain == -1, "the masterchain head is not on the masterchain");
    anyhow::ensure!(info.last.seqno > 0, "the masterchain head has seqno zero");
    anyhow::ensure!(
        info.last.root_hash.len() == 32 && info.last.file_hash.len() == 32,
        "the masterchain head hashes are not 32 bytes"
    );
    Ok(MasterchainCheckpoint {
        seqno: info.last.seqno,
        root_hash: hex::encode(&info.last.root_hash),
        file_hash: hex::encode(&info.last.file_hash),
    })
}

/// Reads proposals of the configuration contract at `address` through `client`.
pub async fn read_proposals(
    client: &ClientJsonRpc,
    address: &MsgAddressInt,
    read: ProposalRead,
) -> anyhow::Result<ProposalAnswer> {
    read_proposals_with(client, address, read, Admission::global()).await
}

/// How a read over every endpoint ended.
enum Outcome<T> {
    /// A terminal classification from some endpoint.
    Settled(Attempt<T>),
    /// No endpoint gave a valid envelope, and some answered successfully with an
    /// oversized body.
    TooLarge { limit: usize },
    /// No endpoint gave a valid envelope or an oversized successful answer.
    Failed(String),
}

type Classify<T> = Arc<dyn Fn(&RawRpcResponse) -> Attempt<T> + Send + Sync>;

/// One request to each endpoint at most, in order, under one id and one permit.
/// A bounded successful body is classified on a worker; an endpoint-specific
/// failure moves on to the next endpoint, anything else settles the read. The
/// next attempt starts only once the previous worker has ended and handed the
/// permit back.
async fn over_endpoints<T: Send + 'static>(
    client: &ClientJsonRpc,
    admission: &Admission,
    mut permit: tokio::sync::OwnedSemaphorePermit,
    method: &'static str,
    params: serde_json::Value,
    classify: Classify<T>,
) -> anyhow::Result<(Outcome<T>, tokio::sync::OwnedSemaphorePermit)> {
    let plan = client.raw_read_plan();
    let total = plan.endpoints.len();
    let mut oversized: Option<usize> = None;
    let mut last_category = "internal";
    for endpoint in plan.endpoints {
        let response = match client.raw_attempt(endpoint, method, &params, &plan.request_id).await {
            RawAttempt::Body(response) => response,
            RawAttempt::TooLarge { limit } => {
                oversized = Some(limit);
                last_category = "response_too_large";
                continue;
            }
            RawAttempt::Failed(category) => {
                last_category = category;
                continue;
            }
        };
        let job = classify.clone();
        let (attempt, returned) = admission.on_worker(permit, move || job(&response)).await?;
        permit = returned;
        match attempt {
            Attempt::Retry(category) => {
                tracing::debug!(
                    method,
                    category,
                    "proposal read answer retried on the next endpoint"
                );
                last_category = category;
            }
            settled => return Ok((Outcome::Settled(settled), permit)),
        }
    }
    let outcome = match oversized {
        Some(limit) => Outcome::TooLarge { limit },
        None => Outcome::Failed(format!(
            "all chain-rpc endpoints failed; endpoint_count={total}; rpc_error_category={last_category}"
        )),
    };
    Ok((outcome, permit))
}

/// [`read_proposals`] under a given admission.
pub async fn read_proposals_with(
    client: &ClientJsonRpc,
    address: &MsgAddressInt,
    read: ProposalRead,
    admission: &Admission,
) -> anyhow::Result<ProposalAnswer> {
    // Admission first: no response of this read, the checkpoint included, is
    // buffered before it holds a worker permit, and it holds that one permit for
    // the whole read.
    let permit = admission.admit().await?;
    let checkpoint = checkpoint(client).await?;
    let params = serde_json::to_value(getter_params(address, read, &checkpoint))?;
    let pinned = checkpoint.clone();
    let classify: Classify<ProposalAnswer> =
        Arc::new(move |response| decode_getter_response(response, read, &pinned));
    let label = read_label(read);
    let (outcome, permit) =
        over_endpoints(client, admission, permit, "runGetMethodStd", params, classify).await?;
    let why = match outcome {
        Outcome::Settled(Attempt::Answer(answer)) => return Ok(answer),
        Outcome::Settled(Attempt::Exit13) => {
            tracing::info!(target: "proposals", "getter returned exit 13; read from stored state");
            "the list_proposals getter returned exit 13".to_string()
        }
        Outcome::Settled(Attempt::Refused(error)) => {
            anyhow::bail!("{label} answer refused: {error}")
        }
        Outcome::Settled(Attempt::Retry(category)) => {
            anyhow::bail!("{label} read failed: {category}")
        }
        Outcome::TooLarge { limit } if read == ProposalRead::List => {
            format!("the list_proposals answer exceeds the {limit}-byte transport limit")
        }
        Outcome::TooLarge { limit } => {
            anyhow::bail!("the {label} answer exceeds the {limit}-byte transport limit")
        }
        Outcome::Failed(message) => anyhow::bail!("{label} read failed: {message}"),
    };
    read_from_state(client, address, read, &checkpoint, admission, permit, why).await
}

/// The large-state path: the contract's stored vote dictionary at the same
/// checkpoint and address, under the read's own permit. Reached only when the list
/// getter's answer exceeded the transport limit on every endpoint that answered
/// successfully, or the getter returned exit 13 at the checkpoint.
async fn read_from_state(
    client: &ClientJsonRpc,
    address: &MsgAddressInt,
    read: ProposalRead,
    checkpoint: &MasterchainCheckpoint,
    admission: &Admission,
    permit: tokio::sync::OwnedSemaphorePermit,
    why: String,
) -> anyhow::Result<ProposalAnswer> {
    anyhow::ensure!(checkpoint.seqno > 0, "a pinned read needs a masterchain seqno above zero");
    let params = serde_json::json!({"address": address.to_string(), "seqno": checkpoint.seqno});
    let pinned = checkpoint.clone();
    let classify: Classify<ProposalAnswer> =
        Arc::new(move |response| decode_account_response(response, read, &pinned));
    let (outcome, _permit) =
        over_endpoints(client, admission, permit, "getAddressInformation", params, classify)
            .await?;
    match outcome {
        Outcome::Settled(Attempt::Answer(answer)) => Ok(answer),
        Outcome::Settled(Attempt::Refused(error)) => {
            anyhow::bail!("{why}; configuration account refused: {error}")
        }
        Outcome::Settled(Attempt::Retry(category)) => {
            anyhow::bail!("{why}; configuration account read failed: {category}")
        }
        Outcome::Settled(Attempt::Exit13) => {
            anyhow::bail!("{why}; configuration account read answered an exit code")
        }
        Outcome::TooLarge { limit } => anyhow::bail!(
            "the vote dictionary is too large to read: {why}, and the configuration \
             contract's stored account exceeds the {limit}-byte transport limit; reading it \
             needs paginated or incremental state reads, which this version does not have"
        ),
        Outcome::Failed(message) => {
            anyhow::bail!("{why}; configuration account read failed: {message}")
        }
    }
}

#[cfg(test)]
#[path = "proposal_transport_tests.rs"]
mod tests;
