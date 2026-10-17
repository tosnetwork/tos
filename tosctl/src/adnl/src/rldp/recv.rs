/*
 * Copyright (C) 2025-2026 RSquad Blockchain Lab.
 *
 * Licensed under the GNU General Public License v3.0.
 * See the LICENSE file in the root of this repository.
 *
 * This software is provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
 */
#[cfg(feature = "debug")]
use crate::rldp::LossFn;
use crate::{
    adnl::common::{AdnlPeers, CountedObject, Counter, TaggedByteSlice},
    declare_counted,
    node::AdnlNode,
    rldp::{Chunk, Constraints, RldpNode, TransferId},
};
use chain_block::{error, fail, Result, UInt256};
#[cfg(feature = "debug")]
use std::sync::atomic::AtomicPtr;
use std::{
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    time::Instant,
};
use tl_api::{
    serialize_bare_inplace,
    tos::{
        fec::{type_::RaptorQ as FecTypeRaptorQ, Type as FecType},
        rldp::messagepart::{
            Complete as RldpComplete, Confirm as RldpConfirm, MessagePart as RldpMessagePart,
        },
        rldp2::messagepart::{
            Complete as Rldp2Complete, Confirm as Rldp2Confirm, MessagePart as Rldp2MessagePart,
        },
    },
};
#[cfg(feature = "telemetry")]
use tl_api::{BareSerialize, Constructor};

enum Complete {
    V1(RldpComplete),
    V2(Rldp2Complete),
}

enum Confirm {
    V1(RldpConfirm),
    V2(Rldp2Confirm),
}

/// RaptorQ decoder
pub struct RaptorqDecoder {
    engine: raptorq::Decoder,
    params: FecTypeRaptorQ,
}

impl RaptorqDecoder {
    /// Largest object a FEC transfer may carry: the C++ ceiling on FEC
    /// broadcasts (`Overlays::max_fec_broadcast_size()`, 16 MiB), which is
    /// also above any RLDP part.
    pub const MAX_DATA_SIZE: i32 = 16 << 20;

    /// The codec configuration both sides use: one source block and one
    /// sub-block, with the symbol size taken as is, which is how the C++
    /// implementation lays out symbols. The default parameters switch to
    /// sub-blocks from about 10 MiB and to several source blocks beyond that,
    /// neither of which the C++ side produces or decodes.
    ///
    /// Symbol size can exceed u16::MAX for two-step broadcasts with few
    /// neighbours, as on the C++ side.
    pub fn config(
        data_size: i32,
        symbol_size: i32,
    ) -> Result<raptorq::ObjectTransmissionInformation> {
        const MAX_SOURCE_SYMBOLS: i64 = 56_403; // K'_max, RFC 6330 section 5.1.2
        if symbol_size <= 0 {
            fail!("Invalid FEC params: symbol_size must be > 0, got {symbol_size}");
        }
        if data_size <= 0 {
            fail!("Invalid FEC params: data_size must be > 0, got {data_size}");
        }
        if data_size > Self::MAX_DATA_SIZE {
            fail!("Invalid FEC params: data_size {data_size} exceeds {}", Self::MAX_DATA_SIZE);
        }
        // Both are positive i32 values, so neither the sum nor the quotient
        // can overflow i64.
        let source_symbols =
            (i64::from(data_size) + i64::from(symbol_size) - 1) / i64::from(symbol_size);
        if source_symbols > MAX_SOURCE_SYMBOLS {
            fail!(
                "Invalid FEC params: source symbol count {source_symbols} exceeds \
                {MAX_SOURCE_SYMBOLS} (data_size={data_size}, symbol_size={symbol_size})"
            );
        }
        Ok(raptorq::ObjectTransmissionInformation::new(
            u64::from(data_size.unsigned_abs()),
            symbol_size.unsigned_abs(),
            1,
            1,
            1,
        ))
    }

    /// Construct with parameters received from a peer. Every bound is checked
    /// before the decoder allocates anything.
    pub fn with_params(params: FecTypeRaptorQ) -> Result<Self> {
        let config = Self::config(params.data_size, params.symbol_size)?;
        Ok(Self { engine: raptorq::Decoder::new(config), params })
    }

    /// Decode one symbol received from a peer.
    ///
    /// The seqno is the symbol's encoding symbol id and must fit in 24 bits;
    /// the symbol must be exactly the negotiated symbol size. Anything else is
    /// refused before it reaches the decoder, as the C++ decoder does.
    pub fn decode(&mut self, seqno: u32, data: &[u8]) -> Result<Option<Vec<u8>>> {
        let symbol_size = usize::try_from(self.params.symbol_size)
            .map_err(|_| error!("Invalid FEC params: symbol_size {}", self.params.symbol_size))?;
        if data.len() != symbol_size {
            fail!("RaptorQ symbol has {} bytes, expected {}", data.len(), symbol_size)
        }
        let payload_id = raptorq::PayloadId::new(0, seqno)
            .map_err(|e| error!("Bad RaptorQ seqno {seqno:#x}: {e}"))?;
        self.engine
            .decode(raptorq::EncodingPacket::new(payload_id, data.to_vec()))
            .map_err(|e| error!("Bad RaptorQ symbol {seqno}: {e}"))
    }

    /// Parameters
    pub fn params(&self) -> &FecTypeRaptorQ {
        &self.params
    }
}

pub(crate) struct RecvContext {
    pub(crate) adnl: Arc<AdnlNode>,
    pub(crate) peers: AdnlPeers,
    pub(crate) queue_reader: tokio::sync::mpsc::UnboundedReceiver<Chunk>,
    pub(crate) recv_transfer: RecvTransfer,
    pub(crate) transfer_id: TransferId,
    #[cfg(feature = "debug")]
    pub(crate) loss_fn: Option<LossFn>,
}

impl RecvContext {
    pub(crate) async fn send_confirmations(&mut self) -> Result<()> {
        let RecvParts::V2(parts) = &mut self.recv_transfer.parts else {
            fail!("RLDP version mismatch in RLDP confirm: expected v2, got v1")
        };
        let Confirm::V2(confirm) = &mut self.recv_transfer.confirm else {
            fail!("RLDP version mismatch in RLDP confirm: expected v2, got v1")
        };
        let elapsed = self.recv_transfer.start.elapsed().as_millis() as u64;
        for i in 0..parts.len() {
            let part = &mut parts[i];
            if (part.confirm_at == 0) || (part.confirm_at > elapsed) {
                continue;
            }
            confirm.part = i as i32;
            confirm.max_seqno = part.core.max_seqno as i32;
            confirm.received_count = part.received_count as i32;
            confirm.received_mask = part.received_mask as i32;
            part.confirm_at = 0;
            serialize_bare_inplace(&mut self.recv_transfer.buf, confirm)?;
            let reply = TaggedByteSlice {
                object: &self.recv_transfer.buf[..],
                #[cfg(feature = "telemetry")]
                tag: Rldp2Confirm::constructor_const(),
            };
            #[cfg(feature = "debug")]
            {
                self.recv_transfer.total_confirm_packets += 1
            }
            self.adnl.send_custom(&reply, &self.peers).await?
        }
        Ok(())
    }
}

struct RecvPart {
    decoder: Option<RaptorqDecoder>,
    max_seqno: u32,
}

impl RecvPart {
    fn new() -> Self {
        Self { decoder: None, max_seqno: 0 }
    }

    fn get_decoder(&mut self, fec_type: FecTypeRaptorQ) -> Result<&mut RaptorqDecoder> {
        let decoder = &mut self.decoder;
        match decoder {
            Some(decoder) => {
                if fec_type != decoder.params {
                    fail!(
                        "Incorrect parameters in RLDP packet: {:?} vs {:?}",
                        fec_type,
                        decoder.params
                    )
                } else {
                    Ok(decoder)
                }
            }
            None => Ok(decoder.insert(RaptorqDecoder::with_params(fec_type)?)),
        }
    }
}

struct RecvPartV1 {
    core: RecvPart,
    confirm_count: usize,
    part: u32,
}

struct RecvPartV2 {
    confirm_at: u64,
    core: RecvPart,
    data: Option<Vec<u8>>,
    received_count: u32,
    received_mask: u32,
}

enum RecvParts {
    V1(RecvPartV1),
    V2(Vec<RecvPartV2>),
}

pub(crate) struct RecvTransfer {
    pub(crate) data: Vec<u8>,
    pub(crate) total_size: Option<usize>,
    #[cfg(feature = "debug")]
    pub(crate) timestamp: Arc<AtomicPtr<Instant>>,
    #[cfg(feature = "debug")]
    pub(crate) total_confirm_packets: u32,
    #[cfg(feature = "debug")]
    pub(crate) total_data_packets: u32,
    buf: Vec<u8>,
    complete: Complete,
    confirm: Confirm,
    parts: RecvParts,
    start: Instant,
    state: Arc<RecvTransferState>,
}

impl RecvTransfer {
    pub(crate) fn new(
        transfer_id: TransferId,
        counter: Arc<AtomicU64>,
        v2: bool,
        #[cfg(feature = "debug")] timestamp: Arc<AtomicPtr<Instant>>,
    ) -> Self {
        let (complete, confirm, parts) = if v2 {
            let complete = Rldp2Complete { transfer_id: UInt256::with_array(transfer_id), part: 0 };
            let confirm = Rldp2Confirm {
                transfer_id: UInt256::with_array(transfer_id),
                part: 0,
                max_seqno: 0,
                received_count: 0,
                received_mask: 0,
            };
            (Complete::V2(complete), Confirm::V2(confirm), RecvParts::V2(Vec::new()))
        } else {
            let complete = RldpComplete { transfer_id: UInt256::with_array(transfer_id), part: 0 };
            let confirm =
                RldpConfirm { transfer_id: UInt256::with_array(transfer_id), part: 0, seqno: 0 };
            let part = RecvPartV1 { core: RecvPart::new(), confirm_count: 0, part: 0 };
            (Complete::V1(complete), Confirm::V1(confirm), RecvParts::V1(part))
        };
        Self {
            buf: Vec::new(),
            complete,
            confirm,
            data: Vec::new(),
            parts,
            start: Instant::now(),
            state: Arc::new(RecvTransferState {
                updates: AtomicU32::new(0),
                counter: counter.into(),
            }),
            #[cfg(feature = "debug")]
            timestamp,
            #[cfg(feature = "debug")]
            total_confirm_packets: 0,
            #[cfg(feature = "debug")]
            total_data_packets: 0,
            total_size: None,
        }
    }

    #[allow(clippy::boxed_local)]
    pub(crate) fn process_chunk(&mut self, chunk: Chunk) -> Result<Option<TaggedByteSlice<'_>>> {
        #[cfg(feature = "debug")]
        {
            self.total_data_packets += 1
        }
        let v2 = if let Confirm::V1(_) = &self.confirm { false } else { true };
        let chunk = match chunk {
            Chunk::V1(RldpMessagePart(chunk)) => {
                if v2 {
                    fail!("RLDP version mismatch in RLDP packet: expected v1, got v2")
                } else {
                    chunk
                }
            }
            Chunk::V2(Rldp2MessagePart(chunk)) => {
                if v2 {
                    chunk
                } else {
                    fail!("RLDP version mismatch in RLDP packet: expected v2, got v1")
                }
            }
        };
        let fec_type = if let FecType::Fec_RaptorQ(fec_type) = chunk.fec_type {
            fec_type
        } else {
            fail!("Unsupported FEC type in RLDP packet")
        };
        let total_size = if let Some(total_size) = self.total_size {
            if total_size != chunk.total_size as usize {
                fail!("Incorrect total size in RLDP packet")
            }
            total_size
        } else {
            let total_size = chunk.total_size as usize;
            if total_size > Constraints::MAX_TRANSFER_SIZE {
                fail!(
                    "RLDP total size {} exceeds maximum {}",
                    total_size,
                    Constraints::MAX_TRANSFER_SIZE
                )
            }
            self.total_size = Some(total_size);
            self.data
                .try_reserve_exact(total_size)
                .map_err(|e| error!("RLDP total size {} is too big: {}", total_size, e))?;
            total_size
        };
        let chunk_part_usize = chunk.part as usize;
        let chunk_seqno_u32 = chunk.seqno as u32;
        let decoder = match &mut self.parts {
            RecvParts::V1(part) => match part.part {
                current_part if current_part == chunk.part as u32 => {
                    if chunk_seqno_u32 > part.core.max_seqno {
                        part.core.max_seqno = chunk_seqno_u32
                    }
                    part.core.get_decoder(fec_type)?
                }
                current_part if current_part > chunk.part as u32 => {
                    return self.build_part_completed_reply(chunk.part)
                }
                _ => return Ok(None),
            },
            RecvParts::V2(parts) => {
                let part = if chunk_part_usize >= parts.len() {
                    let mut in_transit = parts.len();
                    if in_transit > Constraints::MAX_PARTS_IN_TRANSIT {
                        for part in parts.iter() {
                            if part.data.is_none() {
                                break;
                            }
                            in_transit -= 1
                        }
                        if in_transit > Constraints::MAX_PARTS_IN_TRANSIT {
                            fail!(
                                "Too big RLDP part number {}, we did not finish previous {} yet",
                                chunk.part,
                                in_transit
                            )
                        }
                    }
                    while parts.len() <= chunk_part_usize {
                        let part = RecvPartV2 {
                            confirm_at: 0,
                            core: RecvPart::new(),
                            data: None,
                            received_count: 0,
                            received_mask: 0,
                        };
                        parts.push(part)
                    }
                    &mut parts[chunk_part_usize]
                } else if parts[chunk_part_usize].data.is_none() {
                    &mut parts[chunk_part_usize]
                } else {
                    return self.build_part_completed_reply(chunk.part);
                };
                if chunk_seqno_u32 > part.core.max_seqno {
                    let diff = chunk_seqno_u32 - part.core.max_seqno;
                    if diff >= 32 {
                        part.received_mask = 0;
                    } else {
                        part.received_mask <<= diff;
                    }
                    part.core.max_seqno = chunk_seqno_u32;
                }
                let diff = part.core.max_seqno - chunk_seqno_u32;
                if diff < 32 {
                    let mask = 1 << diff;
                    if (part.received_mask & mask) == 0 {
                        part.received_count += 1;
                        part.received_mask |= mask;
                    }
                }
                part.core.get_decoder(fec_type)?
            }
        };
        if let Some(mut data) = decoder.decode(chunk_seqno_u32, &chunk.data)? {
            match &mut self.parts {
                RecvParts::V1(part) => {
                    if data.len() + self.data.len() > total_size {
                        fail!(
                            "Too big size for RLDP transfer {}, expected {}",
                            data.len() + self.data.len(),
                            total_size
                        )
                    } else {
                        self.data.append(&mut data)
                    }
                    if self.data.len() < total_size {
                        part.core.decoder = None;
                        part.core.max_seqno = 0;
                        part.confirm_count = 0;
                        part.part += 1;
                    }
                }
                RecvParts::V2(parts) => {
                    parts[chunk_part_usize].data = Some(data);
                    let mut len = 0;
                    for part in parts.iter() {
                        let Some(data) = &part.data else { break };
                        len += data.len()
                    }
                    if len > total_size {
                        fail!("Too big size for RLDP transfer {}, expected {}", len, total_size)
                    } else if len == total_size {
                        for part in parts {
                            let Some(data) = &mut part.data else {
                                fail!(
                                    "RLDP transfer is completed by size ({}), but not finished",
                                    len
                                )
                            };
                            self.data.append(data)
                        }
                    }
                }
            }
            #[cfg(feature = "debug")]
            RldpNode::check_timestamp(
                &self.timestamp,
                format!("Send part recv complete, seqno {}", chunk.seqno).as_str(),
            );
            self.build_part_completed_reply(chunk.part)
        } else {
            match &mut self.parts {
                RecvParts::V1(part) => {
                    if part.confirm_count == 9 {
                        let Confirm::V1(confirm) = &mut self.confirm else {
                            fail!("RLDP version mismatch in RLDP confirm: expected v2, got v1")
                        };
                        confirm.part = part.part as i32;
                        confirm.seqno = part.core.max_seqno as i32;
                        part.confirm_count = 0;
                        serialize_bare_inplace(&mut self.buf, confirm)?;
                        let ret = TaggedByteSlice {
                            object: &self.buf[..],
                            #[cfg(feature = "telemetry")]
                            tag: RldpConfirm::constructor_const(),
                        };
                        #[cfg(feature = "debug")]
                        {
                            self.total_confirm_packets += 1
                        }
                        Ok(Some(ret))
                    } else {
                        part.confirm_count += 1;
                        Ok(None)
                    }
                }
                RecvParts::V2(parts) => {
                    parts[chunk_part_usize].confirm_at =
                        self.start.elapsed().as_millis() as u64 + RldpNode::ACK_DELAY_MS;
                    Ok(None)
                }
            }
        }
    }

    pub(crate) fn state(&self) -> &Arc<RecvTransferState> {
        &self.state
    }

    fn build_part_completed_reply(&mut self, part: i32) -> Result<Option<TaggedByteSlice<'_>>> {
        match &mut self.complete {
            Complete::V1(complete) => {
                complete.part = part;
                serialize_bare_inplace(&mut self.buf, complete)?;
            }
            Complete::V2(complete) => {
                complete.part = part;
                serialize_bare_inplace(&mut self.buf, complete)?;
            }
        }
        let ret = TaggedByteSlice {
            object: &self.buf[..],
            #[cfg(feature = "telemetry")]
            tag: match &self.complete {
                Complete::V1(complete) => complete.constructor(),
                Complete::V2(complete) => complete.constructor(),
            },
        };
        #[cfg(feature = "debug")]
        {
            self.total_confirm_packets += 1
        }
        Ok(Some(ret))
    }
}

declare_counted!(
    pub(crate) struct RecvTransferState {
        updates: AtomicU32,
    }
);

impl RecvTransferState {
    pub(crate) fn updates(&self) -> u32 {
        self.updates.load(Ordering::Relaxed)
    }
    pub(crate) fn set_updates(&self) {
        self.updates.fetch_add(1, Ordering::Relaxed);
    }
}
