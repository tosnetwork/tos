#![no_main]
// Peer-controlled decoding: an attacker chooses the object size, every
// encoding symbol id and every symbol length, as a remote RLDP or broadcast
// sender does. The decoder must refuse what does not fit and never panic; a
// wrong or absent result is not a finding here (the round trip target covers
// correctness).
//
// Input layout: 3 bytes object size, then repeated records of
//   3 bytes id (low 24 bits) + 1 byte id high bits + 2 bytes length + payload.
// The symbol size is the 768 bytes RLDP uses when the first input byte is
// even, and an unaligned size (two-step broadcast) when it is odd.

use libfuzzer_sys::fuzz_target;
use raptorq::{Decoder, EncodingPacket, ObjectTransmissionInformation, PayloadId};

const MAX_PACKETS: usize = 64;

fuzz_target!(|input: &[u8]| {
    let [a, b, c, rest @ ..] = input else { return };
    let data_size = 1 + u64::from(u32::from_le_bytes([*a, *b, *c, 0]) % 2_000_000);
    let config = if a % 2 == 0 {
        ObjectTransmissionInformation::with_defaults(data_size, 768)
    } else {
        // Keep ceil(data_size / symbol_size) within one source block.
        let symbol_size = 1 + u32::from(*b) * 4 + (data_size / 56_403) as u32;
        ObjectTransmissionInformation::new(data_size, symbol_size, 1, 1, 1)
    };
    let mut decoder = Decoder::new(config);
    let mut rest = rest;
    for _ in 0..MAX_PACKETS {
        let [i0, i1, i2, i3, l0, l1, tail @ ..] = rest else { break };
        let id = u32::from_le_bytes([*i0, *i1, *i2, *i3 & 0x03]);
        let len = usize::from(u16::from_le_bytes([*l0, *l1]) % 2048);
        let take = len.min(tail.len());
        let mut payload = tail[..take].to_vec();
        payload.resize(len, 0);
        rest = &tail[take..];
        // An id of 2^24 or more is refused by PayloadId itself; past that the
        // decoder checks the length and remaps the id.
        let Ok(payload_id) = PayloadId::new(0, id) else { continue };
        let _ = decoder.decode(EncodingPacket::new(payload_id, payload));
    }
});
