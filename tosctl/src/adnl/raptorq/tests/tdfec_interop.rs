//! Differential test against the C++ tdfec RaptorQ implementation.
//!
//! `tests/tdfec/vectors.txt` holds inputs and encoding symbols produced by the
//! C++ encoder (see `tests/tdfec/generate.cpp` for the generator and the
//! command that rebuilds the file). This crate must produce the same bytes for
//! every encoding symbol id, source and repair alike, and must recover the
//! input from the C++ symbols, including when repair symbols are needed and
//! when their ids are close to 2^24.

use raptorq::{Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation, PayloadId};

const VECTORS: &str = include_str!("tdfec/vectors.txt");

struct Case {
    name: String,
    data_size: u64,
    symbol_size: u32,
    source_symbols: u32,
    data: Vec<u8>,
    symbols: Vec<(u32, Vec<u8>)>,
    decode_subset: Vec<u32>,
}

impl Case {
    // The configuration tosctl's RLDP path uses: 768-byte symbols take the
    // default parameters, any other size (two-step broadcast) is used as is.
    fn config(&self) -> ObjectTransmissionInformation {
        if self.symbol_size == 768 {
            ObjectTransmissionInformation::with_defaults(self.data_size, 768)
        } else {
            ObjectTransmissionInformation::new(self.data_size, self.symbol_size, 1, 1, 1)
        }
    }

    fn symbol(&self, encoding_symbol_id: u32) -> &[u8] {
        match self.symbols.iter().find(|(id, _)| *id == encoding_symbol_id) {
            Some((_, bytes)) => bytes,
            None => panic!("{}: no vector for symbol {encoding_symbol_id}", self.name),
        }
    }

    fn packet(&self, encoding_symbol_id: u32) -> EncodingPacket {
        EncodingPacket::new(
            PayloadId::new(0, encoding_symbol_id).unwrap(),
            self.symbol(encoding_symbol_id).to_vec(),
        )
    }
}

fn hex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn cases() -> Vec<Case> {
    let mut cases = vec![];
    let mut current: Option<Case> = None;
    for line in VECTORS.lines() {
        let fields: Vec<&str> = line.split(' ').collect();
        match fields.as_slice() {
            ["case", name, data_size, symbol_size, source_symbols] => {
                current = Some(Case {
                    name: name.to_string(),
                    data_size: data_size.parse().unwrap(),
                    symbol_size: symbol_size.parse().unwrap(),
                    source_symbols: source_symbols.parse().unwrap(),
                    data: vec![],
                    symbols: vec![],
                    decode_subset: vec![],
                })
            }
            ["data", bytes] => current.as_mut().unwrap().data = hex(bytes),
            ["symbol", id, bytes] => {
                current.as_mut().unwrap().symbols.push((id.parse().unwrap(), hex(bytes)))
            }
            ["decode", ids @ ..] => {
                current.as_mut().unwrap().decode_subset =
                    ids.iter().map(|id| id.parse().unwrap()).collect()
            }
            ["end"] => cases.push(current.take().unwrap()),
            _ => panic!("malformed vector line: {line:.40}"),
        }
    }
    assert!(current.is_none(), "unterminated case");
    assert_eq!(cases.len(), 8, "vector file is incomplete");
    for case in &cases {
        assert!(case.data.iter().any(|b| *b != 0), "{}: all-zero input pins nothing", case.name);
    }
    cases
}

#[test]
fn encoder_matches_tdfec_for_source_and_repair_symbols() {
    for case in cases() {
        let encoder = Encoder::new(&case.data, case.config());
        let blocks = encoder.get_block_encoders();
        assert_eq!(blocks.len(), 1, "{}", case.name);
        let block = &blocks[0];
        assert_eq!(block.source_symbol_count(), case.source_symbols, "{}", case.name);
        let source = block.source_packets();
        let mut repair_checked = 0;
        for (id, expected) in &case.symbols {
            let packet = if *id < case.source_symbols {
                source[*id as usize].clone()
            } else {
                repair_checked += 1;
                let mut packets = block.repair_packets(*id, 1).unwrap();
                assert_eq!(packets.len(), 1);
                packets.remove(0)
            };
            assert_eq!(packet.payload_id().encoding_symbol_id(), *id, "{}", case.name);
            assert_eq!(packet.data(), expected.as_slice(), "{}: symbol {id} differs", case.name);
        }
        assert!(repair_checked >= 8, "{}: too few repair vectors", case.name);
    }
}

#[test]
fn decoder_recovers_tdfec_symbols_with_repair() {
    for case in cases() {
        let mut decoder = Decoder::new(case.config());
        let mut result = None;
        let mut repair_used = 0;
        for id in &case.decode_subset {
            if *id >= case.source_symbols {
                repair_used += 1;
            }
            result = decoder.decode(case.packet(*id)).unwrap();
            if result.is_some() {
                break;
            }
        }
        // The subset never contains source symbol 0, so repair symbols (the
        // first two of them with ids near 2^24) must have been used.
        assert!(repair_used >= 1, "{}: no repair symbol used", case.name);
        assert_eq!(result.as_deref(), Some(case.data.as_slice()), "{}", case.name);
    }
}

#[test]
fn decoder_recovers_from_tdfec_repair_symbols_only() {
    for case in cases() {
        let repair: Vec<u32> = case
            .symbols
            .iter()
            .map(|(id, _)| *id)
            .filter(|id| *id >= case.source_symbols)
            .collect();
        let mut decoder = Decoder::new(case.config());
        let mut result = None;
        for id in &repair {
            result = decoder.decode(case.packet(*id)).unwrap();
            if result.is_some() {
                break;
            }
        }
        assert_eq!(result.as_deref(), Some(case.data.as_slice()), "{}", case.name);
    }
}

#[test]
fn tdfec_decodes_what_this_crate_encodes() {
    // The C++ decoder recovered `decode_subset` from its own symbols when the
    // vectors were generated. Symbols from this crate that are byte-identical
    // to those are therefore decodable by the C++ side too; check the identity
    // on exactly that subset, through the encoder entry point RLDP uses.
    for case in cases() {
        let encoder = Encoder::new(&case.data, case.config());
        let packets = encoder.get_encoded_packets(case.source_symbols + 8).unwrap();
        assert_eq!(packets.len() as u32, 2 * case.source_symbols + 8, "{}", case.name);
        for (index, packet) in packets.iter().enumerate() {
            let id = packet.payload_id().encoding_symbol_id();
            assert_eq!(id, index as u32, "{}: ids must run 0, 1, ... without gaps", case.name);
            assert_eq!(packet.data(), case.symbol(id), "{}: symbol {id}", case.name);
        }
        let block = &encoder.get_block_encoders()[0];
        for id in case.decode_subset.iter().filter(|id| **id >= 2 * case.source_symbols + 8) {
            let ours = block.repair_packets(*id, 1).unwrap().remove(0);
            assert_eq!(ours.data(), case.symbol(*id), "{}: symbol {id}", case.name);
        }
    }
}
