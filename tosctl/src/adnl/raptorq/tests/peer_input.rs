//! Peer-supplied symbols, lengths and ids are validated before decoding, and
//! repair decoding through the encoder's own packet stream returns the input.
//! The `regression_*` inputs are the minimised fuzz reproducers of the three
//! defects found by fuzzing this crate: wrong bytes after repair decoding, a
//! panic on a short symbol, and an assertion on an id near 2^24.

use rand::{seq::SliceRandom, Rng, SeedableRng};
use raptorq::{
    Decoder, Encoder, EncodingPacket, Error, ObjectTransmissionInformation, PayloadId,
    SourceBlockDecoder, ENCODING_SYMBOL_ID_LIMIT,
};

const RLDP_SYMBOL: u16 = 768;

fn rldp_config(data_size: u64) -> ObjectTransmissionInformation {
    ObjectTransmissionInformation::with_defaults(data_size, RLDP_SYMBOL)
}

fn random_data(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    (0..len).map(|_| rng.gen()).collect()
}

fn packet(id: u32, data: Vec<u8>) -> EncodingPacket {
    EncodingPacket::new(PayloadId::new(0, id).unwrap(), data)
}

#[test]
fn short_long_and_empty_symbols_are_refused() {
    let config = rldp_config(3000);
    for id in [0, 3, 4, 100, ENCODING_SYMBOL_ID_LIMIT - 1] {
        for len in [0, 1, 767, 769, 1536] {
            let mut decoder = Decoder::new(config);
            assert_eq!(
                decoder.decode(packet(id, vec![0; len])),
                Err(Error::SymbolSizeMismatch { expected: 768, actual: len }),
                "id {id}, length {len}"
            );
        }
    }
}

#[test]
fn a_refused_symbol_leaves_the_decoder_usable() {
    let data = random_data(3000, 1);
    let encoder = Encoder::with_defaults(&data, RLDP_SYMBOL);
    let mut decoder = Decoder::new(encoder.get_config());
    // Garbage first, with the ids of real symbols, then the real symbols.
    assert!(decoder.decode(packet(1, vec![0xaa; 10])).is_err());
    assert!(decoder.decode(packet(4, vec![])).is_err());
    let mut result = None;
    for packet in encoder.get_encoded_packets(4).unwrap().into_iter().skip(1) {
        result = decoder.decode(packet).unwrap();
        if result.is_some() {
            break;
        }
    }
    assert_eq!(result, Some(data.clone()));
    // A complete decoder still refuses a malformed symbol, and still answers.
    assert_eq!(
        decoder.decode(packet(2, vec![0; 5])),
        Err(Error::SymbolSizeMismatch { expected: 768, actual: 5 })
    );
    assert_eq!(decoder.decode(packet(2, vec![0; 768])), Ok(Some(data)));
}

#[test]
fn ids_outside_24_bits_are_refused() {
    for id in [ENCODING_SYMBOL_ID_LIMIT, ENCODING_SYMBOL_ID_LIMIT + 1, 0xff00_0000, u32::MAX] {
        assert_eq!(
            PayloadId::new(0, id),
            Err(Error::EncodingSymbolIdOutOfRange { encoding_symbol_id: id })
        );
    }
    assert!(PayloadId::new(0, ENCODING_SYMBOL_ID_LIMIT - 1).is_ok());
}

#[test]
fn ids_up_to_the_24_bit_limit_decode_without_panic() {
    // The id is remapped to id + K' - K internally, which exceeds 2^24 for the
    // largest wire ids; that must neither panic nor corrupt the result.
    let data = random_data(3000, 2);
    let encoder = Encoder::with_defaults(&data, RLDP_SYMBOL);
    let block = &encoder.get_block_encoders()[0];
    let source = block.source_packets();
    let mut decoder = Decoder::new(encoder.get_config());
    assert_eq!(decoder.decode(source[1].clone()), Ok(None));
    assert_eq!(decoder.decode(source[3].clone()), Ok(None));
    let mut result = None;
    for id in [ENCODING_SYMBOL_ID_LIMIT - 1, ENCODING_SYMBOL_ID_LIMIT - 2, 1_000_000] {
        let repair = block.repair_packets(id, 1).unwrap().remove(0);
        result = decoder.decode(repair).unwrap();
        if result.is_some() {
            break;
        }
    }
    assert_eq!(result, Some(data));
}

#[test]
fn regression_rand_argument_wraps_for_valid_ids() {
    // For these ids y = B + id * A (mod 2^32) is 2^32 - 2 or 2^32 - 1, and the
    // RFC 6330 rand() sum y + i overflowed: wire id 3158218 for K = 978
    // (internal id 3158229), and internal id 8192877 for K = 2153 (wire id
    // 8192835). Both must encode, and decode, without a panic.
    for (k, id) in [(978u32, 3_158_218u32), (2153, 8_192_877 - (2195 - 2153))] {
        let symbol_size = 4u32;
        let data = random_data((k * symbol_size) as usize, u64::from(k));
        let config = ObjectTransmissionInformation::new(data.len() as u64, symbol_size, 1, 1, 1);
        let encoder = Encoder::new(&data, config);
        let block = &encoder.get_block_encoders()[0];
        assert_eq!(block.source_symbol_count(), k);
        let repair = block.repair_packets(id, 1).unwrap().remove(0);
        let mut decoder = Decoder::new(config);
        // Every source symbol but the first, then the wrapping repair symbol.
        for packet in block.source_packets().into_iter().skip(1) {
            assert_eq!(decoder.decode(packet), Ok(None));
        }
        let mut result = decoder.decode(repair).unwrap();
        let mut next = k;
        while result.is_none() {
            result = decoder.decode(block.repair_packets(next, 1).unwrap().remove(0)).unwrap();
            next += 1;
        }
        assert_eq!(result, Some(data), "K = {k}");
    }
}

#[test]
fn foreign_source_blocks_are_refused() {
    let mut decoder = Decoder::new(rldp_config(3000));
    let foreign = EncodingPacket::new(PayloadId::new(1, 0).unwrap(), vec![0; 768]);
    assert_eq!(
        decoder.decode(foreign.clone()),
        Err(Error::SourceBlockOutOfRange { source_block_number: 1, source_blocks: 1 })
    );
    assert_eq!(
        decoder.add_new_packet(foreign.clone()),
        Err(Error::SourceBlockOutOfRange { source_block_number: 1, source_blocks: 1 })
    );
    let mut block_decoder = SourceBlockDecoder::new2(0, &rldp_config(3000), 3000);
    assert_eq!(
        block_decoder.decode([foreign]),
        Err(Error::SourceBlockMismatch { expected: 0, actual: 1 })
    );
}

#[test]
fn truncated_serialized_packets_are_refused() {
    for len in 0..4 {
        assert_eq!(
            EncodingPacket::deserialize(&vec![0; len]),
            Err(Error::PacketTooShort { length: len })
        );
    }
    let packet = EncodingPacket::deserialize(&[0, 0xff, 0xff, 0xff]).unwrap();
    assert_eq!(packet.payload_id().encoding_symbol_id(), ENCODING_SYMBOL_ID_LIMIT - 1);
    assert!(packet.data().is_empty());
}

#[test]
fn repair_ids_are_validated_by_the_encoder() {
    let data = random_data(3000, 3);
    let encoder = Encoder::with_defaults(&data, RLDP_SYMBOL);
    let block = &encoder.get_block_encoders()[0];
    let k = block.source_symbol_count();
    assert_eq!(k, 4);
    for start in [0, 1, k - 1] {
        assert_eq!(
            block.repair_packets(start, 1),
            Err(Error::RepairSymbolIdBelowSourceSymbols {
                encoding_symbol_id: start,
                source_symbols: k
            })
        );
    }
    assert_eq!(
        block.repair_packets(ENCODING_SYMBOL_ID_LIMIT - 1, 2),
        Err(Error::RepairSymbolRangeOverflow { start: ENCODING_SYMBOL_ID_LIMIT - 1, count: 2 })
    );
    assert_eq!(
        block.repair_packets(u32::MAX, 1),
        Err(Error::RepairSymbolRangeOverflow { start: u32::MAX, count: 1 })
    );
    assert_eq!(block.repair_packets(ENCODING_SYMBOL_ID_LIMIT - 1, 1).map(|p| p.len()), Ok(1));
    assert_eq!(block.repair_packets(k, 0), Ok(vec![]));
}

#[test]
fn encoded_packets_carry_distinct_wire_ids() {
    let data = random_data(20_000, 4);
    let encoder = Encoder::with_defaults(&data, RLDP_SYMBOL);
    let packets = encoder.get_encoded_packets(30).unwrap();
    let ids: Vec<u32> = packets.iter().map(|p| p.payload_id().encoding_symbol_id()).collect();
    let expected: Vec<u32> = (0..ids.len() as u32).collect();
    assert_eq!(ids, expected);
}

/// Mirrors the in-tree round-trip fuzz target: encode, shuffle, drop ten
/// packets, decode from the rest.
fn fuzz_round_trip(max_packet_size: u16, data_len: usize, seed: [u8; 32]) {
    let expected_symbols = data_len / max_packet_size as usize;
    let len = if expected_symbols > 56403 { 56403 * max_packet_size as usize } else { data_len };
    let mut rng = rand::rngs::StdRng::from_seed(seed);
    let data: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
    let encoder = Encoder::with_defaults(&data, max_packet_size);
    let mut packets: Vec<Vec<u8>> = encoder
        .get_encoded_packets(expected_symbols as u32 + 20)
        .unwrap()
        .iter()
        .map(|packet| packet.serialize())
        .collect();
    packets.shuffle(&mut rng);
    let length = packets.len();
    packets.truncate(length - 10);
    let mut decoder = Decoder::new(encoder.get_config());
    let mut result = None;
    while let Some(bytes) = packets.pop() {
        result = decoder.decode(EncodingPacket::deserialize(&bytes).unwrap()).unwrap();
        if result.is_some() {
            break;
        }
    }
    assert_eq!(result, Some(data), "mps {max_packet_size}, length {data_len}");
}

#[test]
fn regression_round_trip_with_repair_symbols() {
    // The fuzz target's first failing input: 263-byte packets, 711681 bytes,
    // all-zero seed. It returned wrong bytes without an error.
    fuzz_round_trip(263, 711_681, [0; 32]);
}

#[test]
fn round_trip_with_repair_symbols_across_sizes() {
    // Packets under 64 bytes cannot be split into sub-blocks; deriving their
    // parameters divided by zero before.
    for (mps, len) in
        [(8, 1), (8, 5000), (63, 5000), (256, 4096), (1024, 2048), (768, 3000), (264, 100_000)]
    {
        fuzz_round_trip(mps, len, [7; 32]);
    }
}

/// Mirrors the peer-input harness the reproducers were found with: 3 bytes
/// object size, then records of 3 bytes seqno + 2 bytes length + payload, all
/// fed to an RLDP decoder (768-byte symbols). With `full_symbols` every symbol
/// is 768 bytes regardless of the length field.
fn replay_peer_input(input: &[u8], full_symbols: bool) -> Vec<Result<Option<Vec<u8>>, Error>> {
    let data_size =
        1 + u64::from(u32::from_le_bytes([input[0], input[1], input[2], 0]) % 2_000_000);
    let mut decoder = Decoder::new(rldp_config(data_size));
    let mut rest = &input[3..];
    let mut results = vec![];
    while rest.len() >= 5 && results.len() < 64 {
        let seqno = u32::from_le_bytes([rest[0], rest[1], rest[2], 0]);
        let field = usize::from(u16::from_le_bytes([rest[3], rest[4]]));
        let len = if full_symbols { 768 } else { field % 1025 };
        rest = &rest[5..];
        let take = len.min(rest.len());
        let mut payload = rest[..take].to_vec();
        payload.resize(len, 0);
        rest = &rest[take..];
        results.push(decoder.decode(packet(seqno, payload)));
    }
    results
}

#[test]
fn regression_short_source_symbol() {
    // Base64 "dAEAAAAAAAA=": one empty symbol with id 0. Panicked slicing it.
    let input = [0x74, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(
        replay_peer_input(&input, false),
        vec![Err(Error::SymbolSizeMismatch { expected: 768, actual: 0 })]
    );
}

#[test]
fn regression_short_repair_symbol() {
    // Base64 "egAASAhsBA0=": a 3332 % 1025 = 257-byte repair symbol (id
    // 0x6c0848). Tripped the length assertion in front of the vectorised
    // symbol arithmetic.
    let input = [0x7a, 0x00, 0x00, 0x48, 0x08, 0x6c, 0x04, 0x0d];
    let results = replay_peer_input(&input, false);
    assert_eq!(results.len(), 1);
    assert!(matches!(results[0], Err(Error::SymbolSizeMismatch { expected: 768, .. })));
}

#[test]
fn regression_repair_id_near_24_bit_limit() {
    // Base64 "AHrg/////wo=": a full-size repair symbol with id 0xffffff. The
    // remapped internal id tripped the 24-bit assertion.
    let input = [0x00, 0x7a, 0xe0, 0xff, 0xff, 0xff, 0xff, 0x0a];
    assert_eq!(replay_peer_input(&input, true), vec![Ok(None)]);
}
