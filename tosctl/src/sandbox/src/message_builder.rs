/*
 * Copyright (C) 2025-2026 TOS Blockchain Teams.
 * Licensed under the GNU General Public License v3.0.
 */

//! Fluent builder for constructing internal and external inbound messages.

use chain_block::{
    Cell, CurrencyCollection, ExternalInboundMessageHeader, InternalMessageHeader, Message,
    MsgAddressExt, MsgAddressInt, SliceData, StateInit,
};

/// A fluent builder for constructing TVM [`Message`] values.
///
/// # Examples
///
/// ```ignore
/// // Internal message with 1 TOS and a body
/// let msg = MessageBuilder::internal(&src, &dst, 1_000_000_000)
///     .bounce(true)
///     .body(body_cell)
///     .build();
///
/// // External inbound message
/// let msg = MessageBuilder::external(&dst)
///     .body_slice(body_slice)
///     .build();
/// ```
pub struct MessageBuilder {
    message: Message,
}

impl MessageBuilder {
    /// Create a builder for an internal message.
    ///
    /// The message is created with `ihr_disabled = true` and `bounce = false`
    /// by default. Use [`bounce`](Self::bounce) to override.
    pub fn internal(src: &MsgAddressInt, dst: &MsgAddressInt, value: u64) -> Self {
        let hdr = InternalMessageHeader::with_addresses(
            src.clone(),
            dst.clone(),
            CurrencyCollection::with_coins(value),
        );
        Self { message: Message::with_int_header(hdr) }
    }

    /// Create a builder for an external inbound message.
    ///
    /// The source address is set to `MsgAddressExt::AddrNone` (i.e. off-chain).
    pub fn external(dst: &MsgAddressInt) -> Self {
        let hdr = ExternalInboundMessageHeader::new(MsgAddressExt::AddrNone, dst.clone());
        Self { message: Message::with_ext_in_header(hdr) }
    }

    /// Set the `bounce` flag on the message header.
    ///
    /// Only meaningful for internal messages; ignored for external messages.
    pub fn bounce(mut self, bounce: bool) -> Self {
        if let Some(hdr) = self.message.int_header_mut() {
            hdr.bounce = bounce;
        }
        self
    }

    /// Attach a body [`Cell`] to the message.
    ///
    /// The cell is converted to a [`SliceData`] via serialization.
    pub fn body(mut self, body: Cell) -> Self {
        let slice = SliceData::load_cell_ref(&body).unwrap_or_default();
        self.message.set_body(slice);
        self
    }

    /// Attach a body [`SliceData`] directly.
    pub fn body_slice(mut self, body: SliceData) -> Self {
        self.message.set_body(body);
        self
    }

    /// Attach a [`StateInit`] for contract deployment.
    pub fn state_init(mut self, si: StateInit) -> Self {
        self.message.set_state_init(si);
        self
    }

    /// Consume the builder and produce the final [`Message`].
    pub fn build(self) -> Message {
        self.message
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr(wc: i8, id: u8) -> MsgAddressInt {
        let account_id: chain_block::AccountId = [id; 32].into();
        MsgAddressInt::standard(wc, account_id)
    }

    #[test]
    fn internal_message_round_trip() {
        let src = test_addr(0, 1);
        let dst = test_addr(0, 2);
        let msg = MessageBuilder::internal(&src, &dst, 1_000_000_000).bounce(true).build();

        let hdr = msg.int_header().expect("should be internal");
        assert!(hdr.bounce);
        assert_eq!(hdr.dst, dst);
        assert_eq!(hdr.value, CurrencyCollection::with_coins(1_000_000_000));
    }

    #[test]
    fn external_message_has_no_int_header() {
        let dst = test_addr(0, 3);
        let msg = MessageBuilder::external(&dst).build();

        assert!(msg.int_header().is_none());
        assert!(msg.ext_in_header().is_some());
        let hdr = msg.ext_in_header().unwrap();
        assert_eq!(hdr.dst, dst);
    }
}
