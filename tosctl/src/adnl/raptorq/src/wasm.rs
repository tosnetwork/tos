use crate::{
    base::{EncodingPacket, ObjectTransmissionInformation},
    decoder::Decoder as DecoderNative,
    encoder::Encoder as EncoderNative,
};
use js_sys::Uint8Array;
use std::{string::ToString, vec::Vec};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Decoder {
    decoder: DecoderNative,
}

#[wasm_bindgen]
impl Decoder {
    #[wasm_bindgen]
    pub fn with_defaults(transfer_length: u64, maximum_transmission_unit: u16) -> Decoder {
        let config = ObjectTransmissionInformation::with_defaults(
            transfer_length,
            maximum_transmission_unit,
        );
        Decoder { decoder: DecoderNative::new(config) }
    }

    #[wasm_bindgen]
    pub fn decode(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, JsError> {
        let packet =
            EncodingPacket::deserialize(packet).map_err(|e| JsError::new(&e.to_string()))?;
        self.decoder.decode(packet).map_err(|e| JsError::new(&e.to_string()))
    }
}

#[wasm_bindgen]
pub struct Encoder {
    encoder: EncoderNative,
}

#[wasm_bindgen]
impl Encoder {
    #[wasm_bindgen]
    pub fn with_defaults(data: &[u8], maximum_transmission_unit: u16) -> Encoder {
        Encoder { encoder: EncoderNative::with_defaults(data, maximum_transmission_unit) }
    }

    #[wasm_bindgen]
    pub fn encode(&mut self, repair_packets_per_block: u32) -> Result<Vec<Uint8Array>, JsError> {
        Ok(self
            .encoder
            .get_encoded_packets(repair_packets_per_block)
            .map_err(|e| JsError::new(&e.to_string()))?
            .iter()
            .map(|packet| Uint8Array::from(packet.serialize().as_slice()))
            .collect())
    }
}
