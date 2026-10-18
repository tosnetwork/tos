use crate::{
    base::{
        intermediate_tuple, partition, EncodingPacket, Error, ObjectTransmissionInformation,
        ENCODING_SYMBOL_ID_LIMIT,
    },
    constraint_matrix::{enc_indices, generate_constraint_matrix},
    encoder::SPARSE_MATRIX_THRESHOLD,
    matrix::{BinaryMatrix, DenseBinaryMatrix},
    octet_matrix::DenseOctetMatrix,
    pi_solver::fused_inverse_mul_symbols,
    sparse_matrix::SparseBinaryMatrix,
    symbol::Symbol,
    systematic_constants::{
        calculate_p1, extended_source_block_symbols, num_hdpc_symbols, num_ldpc_symbols,
        num_lt_symbols, num_pi_symbols, systematic_index,
    },
    util::int_div_ceil,
};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeSet as Set, vec::Vec};
#[cfg(not(feature = "std"))]
use core::iter;
#[cfg(feature = "serde_support")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "std")]
use std::{collections::HashSet as Set, iter, vec::Vec};

/// Symbols beyond K that a source block decoder keeps, as in the C++ decoder.
const MAX_EXTRA_SYMBOLS: u32 = 10;

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct Decoder {
    config: ObjectTransmissionInformation,
    block_decoders: Vec<SourceBlockDecoder>,
    blocks: Vec<Option<Vec<u8>>>,
}

impl Decoder {
    pub fn new(config: ObjectTransmissionInformation) -> Decoder {
        let kt = int_div_ceil(config.transfer_length(), config.symbol_size() as u64);

        let (kl, ks, zl, zs) = partition(kt, config.source_blocks());

        let mut decoders = vec![];
        for i in 0..zl {
            decoders.push(SourceBlockDecoder::new2(
                i as u8,
                &config,
                u64::from(kl) * u64::from(config.symbol_size()),
            ));
        }

        for i in zl..(zl + zs) {
            decoders.push(SourceBlockDecoder::new2(
                i as u8,
                &config,
                u64::from(ks) * u64::from(config.symbol_size()),
            ));
        }

        Decoder { config, block_decoders: decoders, blocks: vec![None; (zl + zs) as usize] }
    }

    #[cfg(all(
        any(test, feature = "benchmarking"),
        not(any(feature = "python", feature = "wasm"))
    ))]
    pub fn set_sparse_threshold(&mut self, value: u32) {
        for block_decoder in self.block_decoders.iter_mut() {
            block_decoder.set_sparse_threshold(value);
        }
    }

    /// Adds one packet and returns the object once every block is decoded.
    ///
    /// A packet whose source block number, encoding symbol id or length does
    /// not fit this object is refused with an error and changes nothing.
    pub fn decode(&mut self, packet: EncodingPacket) -> Result<Option<Vec<u8>>, Error> {
        self.add_new_packet(packet)?;
        Ok(self.get_result())
    }

    /// Adds one packet without assembling the result; see [`Decoder::decode`].
    pub fn add_new_packet(&mut self, packet: EncodingPacket) -> Result<(), Error> {
        let source_block_number = packet.payload_id.source_block_number();
        let block_number = usize::from(source_block_number);
        let source_blocks = self.blocks.len();
        let (Some(block), Some(block_decoder)) =
            (self.blocks.get_mut(block_number), self.block_decoders.get_mut(block_number))
        else {
            return Err(Error::SourceBlockOutOfRange { source_block_number, source_blocks });
        };
        if block.is_none() {
            *block = block_decoder.decode(iter::once(packet))?;
        } else {
            // The block is complete; still refuse what does not fit it.
            block_decoder.validate(&packet)?;
        }
        Ok(())
    }

    pub fn get_result(&self) -> Option<Vec<u8>> {
        for block in self.blocks.iter() {
            if block.is_none() {
                return None;
            }
        }

        let mut result = vec![];
        for block in self.blocks.iter().flatten() {
            result.extend(block);
        }
        result.truncate(usize::try_from(self.config.transfer_length()).unwrap_or(usize::MAX));
        Some(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "serde_support", derive(Serialize, Deserialize))]
pub struct SourceBlockDecoder {
    source_block_id: u8,
    symbol_size: u32,
    num_sub_blocks: u16,
    symbol_alignment: u8,
    source_block_symbols: u32,
    source_symbols: Vec<Option<Symbol>>,
    /// Received repair symbols, keyed by internal symbol id (ESI + K' - K).
    repair_symbols: Vec<(u32, Symbol)>,
    received_source_symbols: u32,
    received_esi: Set<u32>,
    decoded: bool,
    /// A symbol was stored since the last solve attempt. Like the C++
    /// decoder's may_decode flag, it keeps duplicate, capped or post-failure
    /// packets from each triggering another full solve.
    may_decode: bool,
    #[cfg(test)]
    solve_attempts: u32,
    sparse_threshold: u32,
}

impl SourceBlockDecoder {
    #[deprecated(
        since = "1.3.0",
        note = "Use the new2() function instead. In version 2.0, that function will replace this one"
    )]
    #[cfg(feature = "std")]
    pub fn new(source_block_id: u8, symbol_size: u32, block_length: u64) -> SourceBlockDecoder {
        let config = ObjectTransmissionInformation::new(0, symbol_size, 0, 1, 1);
        SourceBlockDecoder::new2(source_block_id, &config, block_length)
    }

    // TODO: rename this to new() in version 2.0
    pub fn new2(
        source_block_id: u8,
        config: &ObjectTransmissionInformation,
        block_length: u64,
    ) -> SourceBlockDecoder {
        let source_symbols = int_div_ceil(block_length, config.symbol_size() as u64);

        let mut received_esi = Set::new();
        for i in source_symbols..extended_source_block_symbols(source_symbols) {
            received_esi.insert(i);
        }
        SourceBlockDecoder {
            source_block_id,
            symbol_size: config.symbol_size(),
            num_sub_blocks: config.sub_blocks(),
            symbol_alignment: config.symbol_alignment(),
            source_block_symbols: source_symbols,
            source_symbols: vec![None; source_symbols as usize],
            repair_symbols: vec![],
            received_source_symbols: 0,
            received_esi,
            decoded: false,
            may_decode: false,
            #[cfg(test)]
            solve_attempts: 0,
            sparse_threshold: SPARSE_MATRIX_THRESHOLD,
        }
    }

    #[cfg(any(test, feature = "benchmarking"))]
    pub fn set_sparse_threshold(&mut self, value: u32) {
        self.sparse_threshold = value;
    }

    fn unpack_sub_blocks(&self, result: &mut [u8], symbol: &Symbol, symbol_index: usize) {
        let (tl, ts, nl, ns) =
            partition(self.symbol_size / self.symbol_alignment as u32, self.num_sub_blocks);

        let mut symbol_offset = 0;
        let mut sub_block_offset = 0;
        for sub_block in 0..(nl + ns) {
            let bytes = if sub_block < nl {
                tl as usize * self.symbol_alignment as usize
            } else {
                ts as usize * self.symbol_alignment as usize
            };
            let start = sub_block_offset + bytes * symbol_index;
            result[start..start + bytes]
                .copy_from_slice(&symbol.as_bytes()[symbol_offset..symbol_offset + bytes]);
            symbol_offset += bytes;
            sub_block_offset += bytes * self.source_block_symbols as usize;
        }
    }

    fn try_pi_decode(
        &mut self,
        constraint_matrix: impl BinaryMatrix,
        hdpc_rows: DenseOctetMatrix,
        symbols: Vec<Symbol>,
    ) -> Option<Vec<u8>> {
        let intermediate_symbols = match fused_inverse_mul_symbols(
            constraint_matrix,
            hdpc_rows,
            symbols,
            self.source_block_symbols,
        ) {
            (None, _) => return None,
            (Some(s), _) => s,
        };

        let mut result = vec![0; self.symbol_size as usize * self.source_block_symbols as usize];
        let lt_symbols = num_lt_symbols(self.source_block_symbols);
        let pi_symbols = num_pi_symbols(self.source_block_symbols);
        let sys_index = systematic_index(self.source_block_symbols);
        let p1 = calculate_p1(self.source_block_symbols, pi_symbols);
        for i in 0..self.source_block_symbols as usize {
            if let Some(ref symbol) = self.source_symbols[i] {
                self.unpack_sub_blocks(&mut result, symbol, i);
            } else {
                let rebuilt = self.rebuild_source_symbol(
                    &intermediate_symbols,
                    i as u32,
                    lt_symbols,
                    pi_symbols,
                    sys_index,
                    p1,
                );
                self.unpack_sub_blocks(&mut result, &rebuilt, i);
            }
        }

        self.decoded = true;
        return Some(result);
    }

    /// Checks that a packet belongs to this block, carries an encoding symbol
    /// id below 2^24 and is exactly one symbol long.
    fn validate(&self, packet: &EncodingPacket) -> Result<(), Error> {
        let source_block_number = packet.payload_id.source_block_number();
        if source_block_number != self.source_block_id {
            return Err(Error::SourceBlockMismatch {
                expected: self.source_block_id,
                actual: source_block_number,
            });
        }
        let encoding_symbol_id = packet.payload_id.encoding_symbol_id();
        if encoding_symbol_id >= ENCODING_SYMBOL_ID_LIMIT {
            return Err(Error::EncodingSymbolIdOutOfRange { encoding_symbol_id });
        }
        if packet.data.len() != self.symbol_size as usize {
            return Err(Error::SymbolSizeMismatch {
                expected: self.symbol_size,
                actual: packet.data.len(),
            });
        }
        Ok(())
    }

    /// Adds packets and returns the block once it can be decoded.
    ///
    /// Each packet is validated before it is stored: it must belong to this
    /// block, carry an encoding symbol id below 2^24 and be exactly one symbol
    /// long. The first packet that fails is refused with an error; packets
    /// before it in `packets` are kept, packets after it are not looked at.
    pub fn decode<T: IntoIterator<Item = EncodingPacket>>(
        &mut self,
        packets: T,
    ) -> Result<Option<Vec<u8>>, Error> {
        let num_extended_symbols = extended_source_block_symbols(self.source_block_symbols);
        // K' - K padding symbols sit between the last source symbol and the
        // first repair symbol in internal-symbol-id space.
        let padding = num_extended_symbols.saturating_sub(self.source_block_symbols);
        // The C++ decoder's admission rule (Decoder::add_symbol), ported as is:
        // a source symbol (id < K) is always stored once; a repair symbol is
        // ignored once K + 10 symbols, source and repair together, are held.
        // A block therefore holds at most K source plus K + 10 repair symbols.
        // Capping source symbols too would let dependent repair symbols that
        // arrived first fill the cap and keep the genuine source symbols out,
        // leaving the block undecodable.
        let max_symbols = self.source_block_symbols.saturating_add(MAX_EXTRA_SYMBOLS);
        for packet in packets {
            self.validate(&packet)?;
            let (payload_id, payload) = packet.split();
            let encoding_symbol_id = payload_id.encoding_symbol_id();
            if encoding_symbol_id < self.source_block_symbols {
                if self.received_esi.insert(encoding_symbol_id) {
                    if let Some(slot) = self.source_symbols.get_mut(encoding_symbol_id as usize) {
                        *slot = Some(Symbol::new(payload));
                        self.received_source_symbols =
                            self.received_source_symbols.saturating_add(1);
                        self.may_decode = true;
                    }
                }
            } else {
                let held = self.received_source_symbols as usize + self.repair_symbols.len();
                if held >= max_symbols as usize {
                    continue;
                }
                // Cannot overflow: the id is below 2^24 and the padding below 2^16.
                let internal_symbol_id = encoding_symbol_id.saturating_add(padding);
                if self.received_esi.insert(internal_symbol_id) {
                    self.repair_symbols.push((internal_symbol_id, Symbol::new(payload)));
                    self.may_decode = true;
                }
            }
        }

        if self.received_source_symbols == self.source_block_symbols {
            let mut result =
                vec![0; self.symbol_size as usize * self.source_block_symbols as usize];
            for (i, symbol) in self.source_symbols.iter().enumerate() {
                if let Some(symbol) = symbol {
                    self.unpack_sub_blocks(&mut result, symbol, i);
                }
            }

            self.decoded = true;
            return Ok(Some(result));
        }

        if self.may_decode && self.received_esi.len() as u32 >= num_extended_symbols {
            self.may_decode = false;
            #[cfg(test)]
            {
                self.solve_attempts += 1;
            }
            let s = num_ldpc_symbols(self.source_block_symbols) as usize;
            let h = num_hdpc_symbols(self.source_block_symbols) as usize;

            let mut encoded_indices = vec![];
            // See section 5.3.3.4.2. There are S + H zero symbols to start the D vector
            let mut d = vec![Symbol::zero(self.symbol_size as usize); s + h];
            for (i, source) in self.source_symbols.iter().enumerate() {
                if let Some(symbol) = source {
                    encoded_indices.push(i as u32);
                    d.push(symbol.clone());
                }
            }

            // Append the extended padding symbols
            for i in self.source_block_symbols..num_extended_symbols {
                encoded_indices.push(i);
                d.push(Symbol::zero(self.symbol_size as usize));
            }

            for (internal_symbol_id, symbol) in self.repair_symbols.iter() {
                encoded_indices.push(*internal_symbol_id);
                d.push(symbol.clone());
            }

            if extended_source_block_symbols(self.source_block_symbols) >= self.sparse_threshold {
                let (constraint_matrix, hdpc) = generate_constraint_matrix::<SparseBinaryMatrix>(
                    self.source_block_symbols,
                    &encoded_indices,
                );
                return Ok(self.try_pi_decode(constraint_matrix, hdpc, d));
            } else {
                let (constraint_matrix, hdpc) = generate_constraint_matrix::<DenseBinaryMatrix>(
                    self.source_block_symbols,
                    &encoded_indices,
                );
                return Ok(self.try_pi_decode(constraint_matrix, hdpc, d));
            }
        }
        Ok(None)
    }

    fn rebuild_source_symbol(
        &self,
        intermediate_symbols: &[Symbol],
        source_symbol_id: u32,
        lt_symbols: u32,
        pi_symbols: u32,
        sys_index: u32,
        p1: u32,
    ) -> Symbol {
        let mut rebuilt = Symbol::zero(self.symbol_size as usize);
        let tuple = intermediate_tuple(source_symbol_id, lt_symbols, sys_index, p1);

        for i in enc_indices(tuple, lt_symbols, pi_symbols, p1) {
            rebuilt += &intermediate_symbols[i];
        }
        rebuilt
    }
}

#[cfg(test)]
mod tests {
    use super::{SourceBlockDecoder, Vec, MAX_EXTRA_SYMBOLS};
    use crate::{
        encoder::Encoder, EncodingPacket, Error, ObjectTransmissionInformation, PayloadId,
    };

    #[test]
    fn stored_repair_symbols_are_bounded() {
        // K = 4: at most K + 10 symbols are held however many distinct repair
        // ids a peer sends, so one transfer cannot grow without bound.
        let config = ObjectTransmissionInformation::with_defaults(3000, 768);
        let mut decoder = SourceBlockDecoder::new2(0, &config, 3000);
        let first_repair = decoder.source_block_symbols;
        for id in first_repair..first_repair + 1000 {
            let packet = EncodingPacket::new(PayloadId::new(0, id).unwrap(), vec![0; 768]);
            let _ = decoder.decode([packet]).unwrap();
        }
        assert_eq!(
            decoder.repair_symbols.len() as u32,
            decoder.source_block_symbols + MAX_EXTRA_SYMBOLS
        );
    }

    #[test]
    fn repair_symbols_are_capped_and_sources_stored_once() -> Result<(), Error> {
        // Repairs stop at K + 10 held symbols, but late sources remain admissible.
        let config = ObjectTransmissionInformation::with_defaults(40 * 768, 768);
        let mut decoder = SourceBlockDecoder::new2(0, &config, 40 * 768);
        let k = decoder.source_block_symbols;
        assert_eq!(k, 40);
        let packet = |id| -> Result<EncodingPacket, Error> {
            Ok(EncodingPacket::new(PayloadId::new(0, id)?, vec![5; 768]))
        };
        for id in k..k + 1000 {
            let _ = decoder.decode([packet(id)?])?;
        }
        for _ in 0..3 {
            for id in 0..k {
                let _ = decoder.decode([packet(id)?])?;
            }
        }
        for id in k + 1000..k + 2000 {
            let _ = decoder.decode([packet(id)?])?;
        }
        assert_eq!(decoder.repair_symbols.len() as u32, k + MAX_EXTRA_SYMBOLS);
        assert_eq!(decoder.received_source_symbols, k);
        let held = decoder.received_source_symbols as usize + decoder.repair_symbols.len();
        assert_eq!(held, (2 * k + MAX_EXTRA_SYMBOLS) as usize);

        // Repair admission counts sources already held, not just other repairs.
        let mut sources_first = SourceBlockDecoder::new2(0, &config, 40 * 768);
        for id in 1..k {
            let _ = sources_first.decode([packet(id)?])?;
        }
        for id in k..k + 1000 {
            let _ = sources_first.decode([packet(id)?])?;
        }
        assert_eq!(sources_first.received_source_symbols, k - 1);
        assert_eq!(sources_first.repair_symbols.len() as u32, MAX_EXTRA_SYMBOLS + 1);
        Ok(())
    }

    #[test]
    fn late_source_symbols_recover_a_block_full_of_dependent_repairs() -> Result<(), Error> {
        // Basis bytes expose both source coefficients. Repairs with coefficient
        // zero for the first source cannot recover it, even with distinct ids.
        let mut data = vec![0; 1536];
        data[0] = 1;
        data[769] = 1;
        let config = ObjectTransmissionInformation::new(1536, 768, 1, 1, 1);
        let encoder = Encoder::new(&data, config);
        let block = &encoder.get_block_encoders()[0];
        let k = block.source_symbol_count();
        assert_eq!(k, 2);
        let dependent: Vec<_> = block
            .repair_packets(k, 8192)?
            .into_iter()
            .filter(|packet| packet.data()[0] == 0 && packet.data()[1] != 0)
            .take((k + MAX_EXTRA_SYMBOLS) as usize)
            .collect();
        assert_eq!(dependent.len(), (k + MAX_EXTRA_SYMBOLS) as usize);
        let mut decoder = SourceBlockDecoder::new2(0, &config, 1536);
        for repair in dependent {
            assert_eq!(decoder.decode([repair])?, None);
        }
        assert_eq!(decoder.repair_symbols.len() as u32, k + MAX_EXTRA_SYMBOLS);
        let mut result = None;
        for source in block.source_packets() {
            result = decoder.decode([source])?;
        }
        assert_eq!(result, Some(data));
        Ok(())
    }

    #[test]
    fn only_a_newly_stored_symbol_triggers_a_solve() {
        // K = 4. A solve is attempted once K symbols are held and then once per
        // newly stored symbol up to the K + 10 cap: 11 attempts. Duplicates and
        // symbols past the cap must not each re-run the solver.
        let config = ObjectTransmissionInformation::with_defaults(3000, 768);
        let mut decoder = SourceBlockDecoder::new2(0, &config, 3000);
        let k = decoder.source_block_symbols;
        let repair = |id: u32| EncodingPacket::new(PayloadId::new(0, id).unwrap(), vec![3; 768]);
        for id in k..k + 1000 {
            let _ = decoder.decode([repair(id)]).unwrap();
        }
        for _ in 0..100 {
            let _ = decoder.decode([repair(k)]).unwrap();
        }
        assert_eq!(decoder.solve_attempts, MAX_EXTRA_SYMBOLS + 1);
    }

    #[test]
    fn duplicate_symbols_are_stored_once() {
        let config = ObjectTransmissionInformation::with_defaults(3000, 768);
        let mut decoder = SourceBlockDecoder::new2(0, &config, 3000);
        for _ in 0..3 {
            for id in [1, 7] {
                let packet = EncodingPacket::new(PayloadId::new(0, id).unwrap(), vec![1; 768]);
                assert_eq!(decoder.decode([packet]), Ok(None));
            }
        }
        assert_eq!(decoder.received_source_symbols, 1);
        assert_eq!(decoder.repair_symbols.len(), 1);
    }
}
