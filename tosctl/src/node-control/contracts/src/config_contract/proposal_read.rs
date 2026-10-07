/*
 * Copyright (C) 2025-2026  TOS Network.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
//! Decoding of the configuration contract's `get_proposal` result as the node's
//! `runGetMethodStd` serves it.
//!
//! The getter returns `null()` when the proposal is absent and a nine-element tuple
//! when it is present. The node's serializer tests for a tuple before a list, and a
//! TVM null satisfies only the list test, so an absent proposal arrives as an empty
//! `tvm.stackEntryList`; a non-empty cons list (the voters) arrives as nested
//! two-element tuples ending in that same empty list. Every other shape is refused,
//! including the numeric zero and the unsupported entry, which this serializer emits
//! for no null and which would otherwise make a malformed response read as "absent".
use super::{ConfigProposal, ProposalHash, ProposedParam};
use anyhow::Context;
use common::tvm_stack_parser::TvmStackParser;
use tl_api::tos::tvm::StackEntry;

/// The number of fields `unpack_proposal` returns.
pub const PROPOSAL_FIELDS: usize = 9;

/// A cons list longer than this is not a voter list: voter indices are 16-bit.
const MAX_CONS_LENGTH: usize = 1 << 16;

/// The fields of a present proposal, `None` for an absent one.
fn proposal_fields(stack: &TvmStackParser) -> anyhow::Result<Option<&[StackEntry]>> {
    anyhow::ensure!(
        stack.stack.len() == 1,
        "get_proposal returned {} values, expected 1",
        stack.stack.len()
    );
    let entry = stack.stack.first().context("get_proposal returned no value")?;
    match entry {
        StackEntry::Tvm_StackEntryList(list) if list.list.elements().is_empty() => Ok(None),
        StackEntry::Tvm_StackEntryTuple(tuple) => {
            let fields = tuple.tuple.elements();
            anyhow::ensure!(
                fields.len() == PROPOSAL_FIELDS,
                "get_proposal returned a tuple of {} fields, expected {PROPOSAL_FIELDS}",
                fields.len()
            );
            Ok(Some(fields.as_slice()))
        }
        other => anyhow::bail!(
            "get_proposal returned neither a proposal tuple nor null: {}",
            entry_kind(other)
        ),
    }
}

fn entry_kind(entry: &StackEntry) -> String {
    match entry {
        StackEntry::Tvm_StackEntryCell(_) => "a cell".into(),
        StackEntry::Tvm_StackEntryList(list) => {
            format!("a list of {} elements", list.list.elements().len())
        }
        StackEntry::Tvm_StackEntryNumber(number) => {
            format!("the number {:?}", number.number.number())
        }
        StackEntry::Tvm_StackEntrySlice(_) => "a slice".into(),
        StackEntry::Tvm_StackEntryTuple(tuple) => {
            format!("a tuple of {} elements", tuple.tuple.elements().len())
        }
        StackEntry::Tvm_StackEntryUnsupported => "an unsupported entry".into(),
    }
}

/// A number entry in canonical decimal form: no sign, no leading zero, no whitespace,
/// no fraction, no hexadecimal. This is how the node renders every integer.
fn canonical_unsigned(entry: &StackEntry, what: &str) -> anyhow::Result<u128> {
    let StackEntry::Tvm_StackEntryNumber(number) = entry else {
        anyhow::bail!("{what} is not a number: {}", entry_kind(entry));
    };
    let text = number.number.number();
    let canonical = !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    anyhow::ensure!(canonical, "{what} {text:?} is not a canonical unsigned decimal");
    text.parse::<u128>().with_context(|| format!("{what} {text:?} is out of range"))
}

fn canonical_u32(entry: &StackEntry, what: &str) -> anyhow::Result<u32> {
    let value = canonical_unsigned(entry, what)?;
    u32::try_from(value).with_context(|| format!("{what} {value} exceeds uint32"))
}

fn canonical_u8(entry: &StackEntry, what: &str) -> anyhow::Result<u8> {
    let value = canonical_unsigned(entry, what)?;
    u8::try_from(value).with_context(|| format!("{what} {value} exceeds uint8"))
}

/// The elements of a TVM cons list as the node renders it: an empty list for null,
/// otherwise `[head, tail]` pairs whose last tail is that empty list.
fn cons_list<'a>(entry: &'a StackEntry, what: &str) -> anyhow::Result<Vec<&'a StackEntry>> {
    let mut elements = Vec::new();
    let mut current = entry;
    loop {
        match current {
            StackEntry::Tvm_StackEntryList(list) if list.list.elements().is_empty() => {
                return Ok(elements);
            }
            StackEntry::Tvm_StackEntryTuple(pair) => {
                let [head, tail] = pair.tuple.elements().as_slice() else {
                    anyhow::bail!(
                        "{what} has a cons cell of {} elements, expected 2",
                        pair.tuple.elements().len()
                    );
                };
                anyhow::ensure!(
                    elements.len() < MAX_CONS_LENGTH,
                    "{what} is longer than {MAX_CONS_LENGTH} elements"
                );
                elements.push(head);
                current = tail;
            }
            other => anyhow::bail!("{what} ends in {} instead of null", entry_kind(other)),
        }
    }
}

/// The expiry of the proposal `get_proposal` returned, or `None` when it is absent.
/// Reads only the expiry; the other fields are not this decoder's concern.
pub fn decode_proposal_expiry(stack: &TvmStackParser) -> anyhow::Result<Option<u32>> {
    let Some(fields) = proposal_fields(stack)? else {
        return Ok(None);
    };
    let expires = fields.first().context("proposal has no expiry")?;
    canonical_u32(expires, "proposal expiry").map(Some)
}

/// The whole proposal `get_proposal` returned for `hash`, or `None` when it is absent.
pub fn decode_proposal(
    hash: ProposalHash,
    stack: &TvmStackParser,
) -> anyhow::Result<Option<ConfigProposal>> {
    let Some(fields) = proposal_fields(stack)? else {
        return Ok(None);
    };
    let field = |index: usize| {
        fields.get(index).with_context(|| format!("proposal field {index} is missing"))
    };
    let expires = canonical_u32(field(0)?, "proposal expiry")?;
    let tuple = TvmStackParser::new(fields.to_vec());
    let is_critical = tuple.bool(1).context("proposal critical flag")?;

    // [param_id, param_val, param_hash]
    let param_tuple = tuple.tuple(2).context("proposed parameter")?;
    let id = i32::try_from(param_tuple.i64(0).context("proposed parameter id")?)
        .context("proposed parameter id exceeds int32")?;
    let cell = param_tuple.cell(1).ok();
    let hash_bytes = param_tuple.number_bytes(2, 32).ok().map(|bytes| {
        let mut value = [0u8; 32];
        value.copy_from_slice(&bytes);
        value
    });

    let mut vset_id = [0u8; 32];
    vset_id.copy_from_slice(&tuple.number_bytes(3, 32).context("proposal vset id")?);

    let voters = cons_list(field(4)?, "proposal voter list")?
        .into_iter()
        .map(|voter| {
            let index = canonical_unsigned(voter, "voter index")?;
            u16::try_from(index).with_context(|| format!("voter index {index} exceeds uint16"))
        })
        .collect::<anyhow::Result<Vec<u16>>>()?;

    Ok(Some(ConfigProposal {
        hash,
        expires,
        is_critical,
        param: ProposedParam { id, cell, hash: hash_bytes },
        vset_id,
        voters,
        weight_remaining: tuple.i64(5).context("proposal remaining weight")?,
        rounds_remaining: canonical_u8(field(6)?, "proposal rounds remaining")?,
        losses: canonical_u8(field(7)?, "proposal losses")?,
        wins: canonical_u8(field(8)?, "proposal wins")?,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tl_api::tos::tvm::{
        List, Number, Tuple, list,
        numberdecimal::NumberDecimal,
        stackentry::{StackEntryList, StackEntryNumber, StackEntryTuple},
        tuple,
    };

    fn number(text: &str) -> StackEntry {
        StackEntry::Tvm_StackEntryNumber(StackEntryNumber {
            number: Number::Tvm_NumberDecimal(NumberDecimal { number: text.to_string() }),
        })
    }

    fn null() -> StackEntry {
        StackEntry::Tvm_StackEntryList(StackEntryList {
            list: List::Tvm_List(list::List { elements: vec![] }),
        })
    }

    fn tuple_of(elements: Vec<StackEntry>) -> StackEntry {
        StackEntry::Tvm_StackEntryTuple(StackEntryTuple {
            tuple: Tuple::Tvm_Tuple(tuple::Tuple { elements }),
        })
    }

    /// `cons(a, cons(b, ... null))`, as the node renders it.
    fn cons(items: &[&str]) -> StackEntry {
        items.iter().rev().fold(null(), |tail, item| tuple_of(vec![number(item), tail]))
    }

    fn proposal(expires: &str, voters: StackEntry) -> StackEntry {
        tuple_of(vec![
            number(expires),
            number("0"),
            tuple_of(vec![number("42"), null(), number("-1")]),
            number("12345"),
            voters,
            number("1000"),
            number("3"),
            number("0"),
            number("1"),
        ])
    }

    fn stack(entries: Vec<StackEntry>) -> TvmStackParser {
        TvmStackParser::new(entries)
    }

    #[test]
    fn absent_and_present_proposals() {
        assert_eq!(decode_proposal_expiry(&stack(vec![null()])).unwrap(), None);
        let present = stack(vec![proposal("1793250000", null())]);
        assert_eq!(decode_proposal_expiry(&present).unwrap(), Some(1_793_250_000));
        let max = stack(vec![proposal("4294967295", cons(&["1"]))]);
        assert_eq!(decode_proposal_expiry(&max).unwrap(), Some(u32::MAX));

        assert!(decode_proposal([1; 32], &stack(vec![null()])).unwrap().is_none());
        let full = decode_proposal([1; 32], &present).unwrap().unwrap();
        assert_eq!(full.expires, 1_793_250_000);
        assert!(full.voters.is_empty());
        assert_eq!(full.param.id, 42);
        assert!(full.param.cell.is_none());
        assert!(full.param.hash.is_none());
        assert_eq!((full.rounds_remaining, full.losses, full.wins), (3, 0, 1));
        let voted = stack(vec![proposal("10", cons(&["0", "7", "65535"]))]);
        assert_eq!(decode_proposal([1; 32], &voted).unwrap().unwrap().voters, vec![0, 7, 65535]);
    }

    /// The expiry decoder reads the expiry and the arity only: a field it does not
    /// need cannot make a registered proposal unreadable.
    #[test]
    fn the_expiry_decoder_ignores_the_other_fields() {
        let odd = tuple_of(vec![
            number("77"),
            null(),
            null(),
            null(),
            number("5"),
            null(),
            null(),
            null(),
            null(),
        ]);
        assert_eq!(decode_proposal_expiry(&stack(vec![odd])).unwrap(), Some(77));
    }

    #[test]
    fn malformed_results_are_refused() {
        let unsupported = StackEntry::Tvm_StackEntryUnsupported;
        let short = vec![number("1"); PROPOSAL_FIELDS - 1];
        let long = vec![number("1"); PROPOSAL_FIELDS + 1];
        for (case, entries) in [
            ("empty stack", vec![]),
            ("two values", vec![null(), null()]),
            ("numeric zero", vec![number("0")]),
            ("unsupported", vec![unsupported]),
            ("non-empty flat list", vec![cons_flat(&["1"])]),
            ("eight fields", vec![tuple_of(short)]),
            ("ten fields", vec![tuple_of(long)]),
        ] {
            let error = decode_proposal_expiry(&stack(entries.clone()));
            assert!(error.is_err(), "{case}: {error:?}");
            assert!(decode_proposal([0; 32], &stack(entries)).is_err(), "{case}");
        }
    }

    fn cons_flat(items: &[&str]) -> StackEntry {
        StackEntry::Tvm_StackEntryList(StackEntryList {
            list: List::Tvm_List(list::List {
                elements: items.iter().map(|i| number(i)).collect(),
            }),
        })
    }

    #[test]
    fn non_canonical_or_out_of_range_expiries_are_refused() {
        for bad in [
            "4294967296",
            "-1",
            "+1",
            "007",
            " 1",
            "1 ",
            "1.5",
            "1.0",
            "0x10",
            "",
            "1e3",
            "99999999999999999999999999999999999999999",
        ] {
            let result = decode_proposal_expiry(&stack(vec![proposal(bad, null())]));
            assert!(result.is_err(), "{bad:?} was accepted: {result:?}");
            assert!(decode_proposal([0; 32], &stack(vec![proposal(bad, null())])).is_err());
        }
        assert_eq!(decode_proposal_expiry(&stack(vec![proposal("0", null())])).unwrap(), Some(0));
    }

    #[test]
    fn malformed_voter_lists_are_refused() {
        let pair = |head: StackEntry, tail: StackEntry| tuple_of(vec![head, tail]);
        for (case, voters) in [
            ("numeric nil tail", pair(number("1"), number("0"))),
            ("unsupported tail", pair(number("1"), StackEntry::Tvm_StackEntryUnsupported)),
            ("non-empty list tail", pair(number("1"), cons_flat(&["2"]))),
            ("three-element cell", tuple_of(vec![number("1"), number("2"), null()])),
            ("one-element cell", tuple_of(vec![number("1")])),
            ("flat list", cons_flat(&["1", "2"])),
            ("index above uint16", cons(&["65536"])),
            ("negative index", cons(&["-1"])),
            ("non-number index", pair(null(), null())),
        ] {
            let result = decode_proposal([0; 32], &stack(vec![proposal("10", voters)]));
            assert!(result.is_err(), "{case} was accepted");
        }
    }
}
