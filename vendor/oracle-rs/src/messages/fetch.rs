//! Fetch message for retrieving rows from a cursor
//!
//! This module implements the fetch message used to retrieve additional
//! rows from an already-executed query cursor.

use bytes::{BufMut, Bytes, BytesMut};

use crate::buffer::WriteBuffer;
use crate::capabilities::Capabilities;
use crate::constants::{FetchOrientation, FunctionCode, MessageType, PacketType, PACKET_HEADER_SIZE};
use crate::error::Result;

use super::token::{NON_PIPELINED_TOKEN_NUMBER, write_request_token};

/// Fetch message to retrieve rows from a cursor
#[derive(Debug)]
pub struct FetchMessage {
    /// Cursor ID to fetch from
    cursor_id: u16,
    /// Number of rows to fetch
    num_rows: u32,
    /// Fetch orientation for scrollable cursors
    orientation: Option<FetchOrientation>,
    /// Fetch offset/position for scrollable cursors
    offset: i64,
    /// Per-connection TTC sequence number
    sequence_number: u8,
}

impl FetchMessage {
    /// Create a new fetch message
    pub fn new(cursor_id: u16, num_rows: u32) -> Self {
        Self {
            cursor_id,
            num_rows,
            orientation: None,
            offset: 0,
            sequence_number: 0,
        }
    }

    /// Create a new scrollable fetch message
    pub fn new_scrollable(
        cursor_id: u16,
        num_rows: u32,
        orientation: FetchOrientation,
        offset: i64,
    ) -> Self {
        Self {
            cursor_id,
            num_rows,
            orientation: Some(orientation),
            offset,
            sequence_number: 0,
        }
    }

    /// Set the per-connection TTC sequence number.
    pub fn set_sequence_number(&mut self, sequence_number: u8) {
        self.sequence_number = sequence_number;
    }

    /// Build the fetch request packet
    pub fn build_request(&self, caps: &Capabilities) -> Result<Bytes> {
        let mut buf = WriteBuffer::new();

        // Write message header
        buf.write_u8(MessageType::Function as u8)?;
        buf.write_u8(FunctionCode::Fetch as u8)?;
        buf.write_u8(self.sequence_number)?;
        write_request_token(&mut buf, caps, NON_PIPELINED_TOKEN_NUMBER)?;

        // Write fetch body
        buf.write_ub4(self.cursor_id as u32)?;
        buf.write_ub4(self.num_rows)?;

        // Write scrollable cursor fields if present
        if let Some(orientation) = self.orientation {
            buf.write_ub4(orientation as u32)?; // Fetch orientation
            buf.write_ub4(self.offset as u32)?; // Fetch position (for absolute/relative)
        }

        // Build packet with header
        let payload = buf.freeze();
        let packet_len = PACKET_HEADER_SIZE + payload.len();

        let mut packet = BytesMut::with_capacity(packet_len);

        // Packet header
        packet.put_u16(packet_len as u16); // Length
        packet.put_u16(0); // Checksum
        packet.put_u8(PacketType::Data as u8);
        packet.put_u8(0); // Flags
        packet.put_u16(0); // Header checksum

        // Data flags (2 bytes)
        packet.put_u16(0);

        // Payload
        packet.extend_from_slice(&payload);

        Ok(packet.freeze())
    }

    /// Get the cursor ID
    pub fn cursor_id(&self) -> u16 {
        self.cursor_id
    }

    /// Get the number of rows to fetch
    pub fn num_rows(&self) -> u32 {
        self.num_rows
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_message_creation() {
        let msg = FetchMessage::new(1, 100);
        assert_eq!(msg.cursor_id(), 1);
        assert_eq!(msg.num_rows(), 100);
    }

    #[test]
    fn test_fetch_message_builds_packet() {
        let mut msg = FetchMessage::new(1, 100);
        msg.set_sequence_number(7);
        let caps = Capabilities::new();

        let packet = msg.build_request(&caps).unwrap();

        // Check packet header
        assert!(packet.len() > PACKET_HEADER_SIZE);
        assert_eq!(packet[4], PacketType::Data as u8);

        // Check data flags are present
        assert_eq!(packet[8], 0);
        assert_eq!(packet[9], 0);

        // Check function type (byte 10) is Function (3)
        assert_eq!(packet[10], MessageType::Function as u8);

        // Check function code (byte 11) is Fetch (5)
        assert_eq!(packet[11], FunctionCode::Fetch as u8);

        let mut payload = crate::buffer::ReadBuffer::from_slice(&packet[PACKET_HEADER_SIZE..]);
        assert_eq!(payload.read_u16_be().unwrap(), 0);
        assert_eq!(payload.read_u8().unwrap(), MessageType::Function as u8);
        assert_eq!(payload.read_u8().unwrap(), FunctionCode::Fetch as u8);
        assert_eq!(payload.read_u8().unwrap(), 7);
        assert_eq!(payload.read_ub8().unwrap(), NON_PIPELINED_TOKEN_NUMBER);
        assert_eq!(payload.read_ub4().unwrap(), 1);
        assert_eq!(payload.read_ub4().unwrap(), 100);
        assert_eq!(payload.remaining(), 0);
    }

    #[test]
    fn legacy_fetch_omits_the_token_without_shifting_its_body() {
        let mut msg = FetchMessage::new(3, 25);
        msg.set_sequence_number(9);
        let mut caps = Capabilities::new();
        caps.ttc_field_version = crate::constants::ccap_value::FIELD_VERSION_23_1;

        let packet = msg.build_request(&caps).unwrap();
        let mut payload = crate::buffer::ReadBuffer::from_slice(&packet[PACKET_HEADER_SIZE..]);
        assert_eq!(payload.read_u16_be().unwrap(), 0);
        assert_eq!(payload.read_u8().unwrap(), MessageType::Function as u8);
        assert_eq!(payload.read_u8().unwrap(), FunctionCode::Fetch as u8);
        assert_eq!(payload.read_u8().unwrap(), 9);
        assert_eq!(payload.read_ub4().unwrap(), 3);
        assert_eq!(payload.read_ub4().unwrap(), 25);
        assert_eq!(payload.remaining(), 0);
    }
}
