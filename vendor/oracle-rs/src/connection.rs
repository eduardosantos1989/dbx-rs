//! Oracle database connection
//!
//! This module provides the main `Connection` type for interacting with Oracle databases.
//!
//! # Example
//!
//! ```rust,ignore
//! use oracle_rs::{Connection, Config};
//!
//! #[tokio::main]
//! async fn main() -> oracle_rs::Result<()> {
//!     // Create a connection
//!     let conn = Connection::connect("localhost:1521/ORCLPDB1", "user", "password").await?;
//!
//!     // Execute a query
//!     let rows = conn.query("SELECT * FROM employees WHERE department_id = :1", &[&10]).await?;
//!
//!     for row in rows {
//!         println!("{:?}", row);
//!     }
//!
//!     // Commit and close
//!     conn.commit().await?;
//!     conn.close().await?;
//!     Ok(())
//! }
//! ```

use bytes::Bytes;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};
use tokio::sync::Mutex;

use crate::batch::{BatchBinds, BatchResult};
use crate::buffer::{ReadBuffer, WriteBuffer};
use crate::capabilities::Capabilities;
use crate::config::{Config, ServiceMethod, ValueDecodePolicy, WireLimits};
use crate::constants::{
    BindDirection, FetchOrientation, FunctionCode, MessageType, OracleType, PacketType,
    PACKET_HEADER_SIZE,
};
use crate::cursor::{ScrollResult, ScrollableCursor};
use crate::error::{Error, Result};
use crate::implicit::{ImplicitResult, ImplicitResults};
use crate::messages::{
    parse_error_info_with_rowcount_for_version, validate_response_token, write_request_token,
    AcceptMessage, AuthMessage, AuthPhase, ConnectMessage, ExecuteMessage, ExecuteOptions,
    FetchMessage, LobOpMessage, NON_PIPELINED_TOKEN_NUMBER,
};
use crate::packet::Packet;
use crate::row::{Row, Value};
use crate::statement::{BindParam, ColumnInfo, Statement, StatementType};
use crate::statement_cache::StatementCache;
use crate::transport::{connect_tls, TlsConfig, TlsOracleStream};
use crate::types::{LobData, LobLocator, LobValue};

const MAX_RESPONSE_PACKETS: usize = 4096;

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    /// Not connected
    Disconnected,
    /// TCP connection established
    Connected,
    /// Protocol negotiation complete
    ProtocolNegotiated,
    /// Data types negotiated
    DataTypesNegotiated,
    /// Fully authenticated and ready
    Ready,
    /// Connection is closed
    Closed,
}

/// Options for query execution
#[derive(Debug, Clone)]
pub struct QueryOptions {
    /// Number of rows to prefetch
    pub prefetch_rows: u32,
    /// Array size for batch operations
    pub array_size: u32,
    /// Whether to auto-commit after DML
    pub auto_commit: bool,
}

impl Default for QueryOptions {
    fn default() -> Self {
        Self {
            prefetch_rows: 100,
            array_size: 100,
            auto_commit: false,
        }
    }
}

/// Result set from a query
#[derive(Debug)]
pub struct QueryResult {
    /// Column information
    pub columns: Vec<ColumnInfo>,
    /// Rows returned
    pub rows: Vec<Row>,
    /// Number of rows affected (for DML)
    pub rows_affected: u64,
    /// Whether there are more rows to fetch
    pub has_more_rows: bool,
    /// Cursor ID for subsequent fetches (needed for fetch_more)
    pub cursor_id: u16,
    /// Number of TNS packets assembled for this response
    pub response_packet_count: usize,
}

impl QueryResult {
    /// Create an empty query result
    pub fn empty() -> Self {
        Self {
            columns: Vec::new(),
            rows: Vec::new(),
            rows_affected: 0,
            has_more_rows: false,
            cursor_id: 0,
            response_packet_count: 0,
        }
    }

    /// Get the number of columns
    pub fn column_count(&self) -> usize {
        self.columns.len()
    }

    /// Get the number of rows
    pub fn row_count(&self) -> usize {
        self.rows.len()
    }

    /// Check if the result is empty
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Get a column by name
    pub fn column_by_name(&self, name: &str) -> Option<&ColumnInfo> {
        self.columns
            .iter()
            .find(|c| c.name.eq_ignore_ascii_case(name))
    }

    /// Get column index by name
    pub fn column_index(&self, name: &str) -> Option<usize> {
        self.columns
            .iter()
            .position(|c| c.name.eq_ignore_ascii_case(name))
    }

    /// Iterate over rows
    pub fn iter(&self) -> impl Iterator<Item = &Row> {
        self.rows.iter()
    }

    /// Get a single row (first row)
    pub fn first(&self) -> Option<&Row> {
        self.rows.first()
    }
}

impl IntoIterator for QueryResult {
    type Item = Row;
    type IntoIter = std::vec::IntoIter<Row>;

    fn into_iter(self) -> Self::IntoIter {
        self.rows.into_iter()
    }
}

/// Result from executing a PL/SQL block with OUT parameters
#[derive(Debug)]
pub struct PlsqlResult {
    /// OUT parameter values indexed by position (0-based)
    pub out_values: Vec<Value>,
    /// Number of rows affected (if applicable)
    pub rows_affected: u64,
    /// Cursor ID (if the result contains a REF CURSOR)
    pub cursor_id: Option<u16>,
    /// Implicit result sets returned via DBMS_SQL.RETURN_RESULT
    pub implicit_results: ImplicitResults,
}

impl PlsqlResult {
    /// Create an empty PL/SQL result
    pub fn empty() -> Self {
        Self {
            out_values: Vec::new(),
            rows_affected: 0,
            cursor_id: None,
            implicit_results: ImplicitResults::new(),
        }
    }

    /// Get an OUT value by position (0-based)
    pub fn get(&self, index: usize) -> Option<&Value> {
        self.out_values.get(index)
    }

    /// Get a string OUT value by position
    pub fn get_string(&self, index: usize) -> Option<&str> {
        self.out_values.get(index).and_then(|v| v.as_str())
    }

    /// Get an integer OUT value by position
    pub fn get_integer(&self, index: usize) -> Option<i64> {
        self.out_values.get(index).and_then(|v| v.as_i64())
    }

    /// Get a float OUT value by position
    pub fn get_float(&self, index: usize) -> Option<f64> {
        self.out_values.get(index).and_then(|v| v.as_f64())
    }

    /// Get a cursor ID from OUT value by position (for REF CURSOR)
    pub fn get_cursor_id(&self, index: usize) -> Option<u16> {
        self.out_values.get(index).and_then(|v| v.as_cursor_id())
    }
}

/// Server information obtained during connection
#[derive(Debug, Clone, Default)]
pub struct ServerInfo {
    /// Oracle version string
    pub version: String,
    /// Server banner
    pub banner: String,
    /// Session ID (SID)
    pub session_id: u32,
    /// Serial number
    pub serial_number: u32,
    /// Instance name
    pub instance_name: Option<String>,
    /// Service name
    pub service_name: Option<String>,
    /// Database name
    pub database_name: Option<String>,
    /// Negotiated protocol version
    pub protocol_version: u16,
    /// Whether server supports OOB (out of band) data
    pub supports_oob: bool,
}

/// Stream type that can be either plain TCP or TLS-encrypted
enum OracleStream {
    /// Plain TCP connection
    Plain(TcpStream),
    /// TLS-encrypted connection
    Tls(TlsOracleStream),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectResendAction {
    Replay,
    RenegotiateTls,
}

fn connect_resend_action(tls_enabled: bool, packet_flags: u8) -> Result<ConnectResendAction> {
    if packet_flags & crate::constants::packet_flags::TLS_RENEG == 0 {
        return Ok(ConnectResendAction::Replay);
    }
    if tls_enabled {
        Ok(ConnectResendAction::RenegotiateTls)
    } else {
        Err(Error::ProtocolError(
            "Server requested TLS renegotiation on a plaintext connection".to_string(),
        ))
    }
}

impl OracleStream {
    async fn read_exact(&mut self, buf: &mut [u8]) -> std::io::Result<()> {
        match self {
            OracleStream::Plain(stream) => {
                AsyncReadExt::read_exact(stream, buf).await?;
                Ok(())
            }
            OracleStream::Tls(stream) => {
                AsyncReadExt::read_exact(stream, buf).await?;
                Ok(())
            }
        }
    }

    async fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        match self {
            OracleStream::Plain(stream) => stream.write_all(buf).await,
            OracleStream::Tls(stream) => stream.write_all(buf).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            OracleStream::Plain(stream) => stream.flush().await,
            OracleStream::Tls(stream) => stream.flush().await,
        }
    }
}

/// Internal connection state shared across async operations
struct ConnectionInner {
    stream: Option<OracleStream>,
    capabilities: Capabilities,
    state: ConnectionState,
    server_info: ServerInfo,
    sdu_size: u16,
    large_sdu: bool,
    /// Sequence number for TTC messages (increments per message)
    sequence_number: u8,
    /// Statement cache for prepared statement reuse
    statement_cache: Option<StatementCache>,
    wire_limits: WireLimits,
}

impl ConnectionInner {
    fn new_with_cache(cache_size: usize, wire_limits: WireLimits) -> Self {
        Self {
            stream: None,
            capabilities: Capabilities::default(),
            state: ConnectionState::Disconnected,
            server_info: ServerInfo::default(),
            sdu_size: 8192,
            large_sdu: false,
            sequence_number: 0,
            statement_cache: if cache_size > 0 {
                Some(StatementCache::new(cache_size))
            } else {
                None
            },
            wire_limits,
        }
    }

    /// Get the next sequence number (auto-increments, wraps at 255 to 1)
    fn next_sequence_number(&mut self) -> u8 {
        self.sequence_number = self.sequence_number.wrapping_add(1);
        if self.sequence_number == 0 {
            self.sequence_number = 1;
        }
        self.sequence_number
    }

    async fn send(&mut self, data: &[u8]) -> Result<()> {
        if let Some(stream) = &mut self.stream {
            stream.write_all(data).await?;
            stream.flush().await?;
            Ok(())
        } else {
            Err(Error::ConnectionClosed)
        }
    }

    /// Send a payload that may need to be split across multiple packets.
    ///
    /// This is used for large LOB writes and other operations where the payload
    /// exceeds the SDU size. The payload is split into multiple DATA packets,
    /// each with proper headers.
    ///
    /// # Arguments
    /// * `payload` - The raw message payload (without packet header or data flags)
    /// * `data_flags` - The data flags for the first packet (typically 0)
    async fn send_multi_packet(&mut self, payload: &[u8], data_flags: u16) -> Result<()> {
        let stream = self.stream.as_mut().ok_or(Error::ConnectionClosed)?;

        // Calculate max payload per packet: SDU - header (8) - data flags (2)
        let max_payload_per_packet = self.sdu_size as usize - PACKET_HEADER_SIZE - 2;

        let mut offset = 0;
        let mut is_first = true;

        while offset < payload.len() {
            let remaining = payload.len() - offset;
            let chunk_size = std::cmp::min(remaining, max_payload_per_packet);
            let is_last = offset + chunk_size >= payload.len();

            // Build packet
            let packet_len = PACKET_HEADER_SIZE + 2 + chunk_size; // header + data flags + payload
            let mut packet = Vec::with_capacity(packet_len);

            // Header
            if self.large_sdu {
                packet.extend_from_slice(&(packet_len as u32).to_be_bytes());
            } else {
                packet.extend_from_slice(&(packet_len as u16).to_be_bytes());
                packet.extend_from_slice(&[0, 0]); // Checksum
            }
            packet.push(PacketType::Data as u8);
            packet.push(0); // Flags
            packet.extend_from_slice(&[0, 0]); // Header checksum

            // Data flags - only include on first packet
            if is_first {
                packet.extend_from_slice(&data_flags.to_be_bytes());
                is_first = false;
            } else {
                // Continuation packets still need data flags position but value is 0
                packet.extend_from_slice(&0u16.to_be_bytes());
            }

            // Payload chunk
            packet.extend_from_slice(&payload[offset..offset + chunk_size]);

            // Send this packet
            stream.write_all(&packet).await?;

            offset += chunk_size;

            // Don't flush until the last packet to improve performance
            if is_last {
                stream.flush().await?;
            }
        }

        Ok(())
    }

    async fn receive(&mut self) -> Result<bytes::Bytes> {
        if let Some(stream) = &mut self.stream {
            // Read packet header first (always 8 bytes)
            // large_sdu only affects how the length field is interpreted, not header size
            let mut header_buf = vec![0u8; PACKET_HEADER_SIZE];
            stream.read_exact(&mut header_buf).await?;

            // Parse header to get payload length
            // In large_sdu mode, first 4 bytes are length; otherwise first 2 bytes
            let packet_len = if self.large_sdu {
                u32::from_be_bytes([header_buf[0], header_buf[1], header_buf[2], header_buf[3]])
                    as usize
            } else {
                u16::from_be_bytes([header_buf[0], header_buf[1]]) as usize
            };

            // Read remaining payload
            if !(PACKET_HEADER_SIZE..=self.wire_limits.max_packet_bytes).contains(&packet_len) {
                return Err(Error::LimitExceeded);
            }
            let payload_len = packet_len - PACKET_HEADER_SIZE;
            let mut payload_buf = vec![0u8; payload_len];
            if payload_len > 0 {
                stream.read_exact(&mut payload_buf).await?;
            }

            // Combine header and payload
            let mut full_packet = header_buf.clone();
            full_packet.extend(payload_buf);

            Ok(bytes::Bytes::from(full_packet))
        } else {
            Err(Error::ConnectionClosed)
        }
    }

    /// Receive a complete response that may span multiple packets
    ///
    /// This method accumulates packets until the END_OF_RESPONSE flag is detected
    /// in the data flags. It's used for operations like LOB reads that may return
    /// data spanning multiple TNS packets.
    ///
    /// Returns the combined payload of all packets (excluding headers).
    async fn receive_response(&mut self) -> Result<bytes::Bytes> {
        use crate::constants::{data_flags, MessageType};

        let mut accumulated_payload = Vec::new();
        let mut is_first_packet = true;
        let mut packet_count = 0_usize;

        loop {
            let packet = self.receive().await?;
            packet_count = increment_response_packet_count(packet_count)?;

            if packet.len() < PACKET_HEADER_SIZE {
                return Err(Error::Protocol("Packet too small".to_string()));
            }

            // Check packet type - only DATA packets can be accumulated
            let packet_type = packet[4];
            if packet_type != PacketType::Data as u8 {
                // Non-DATA packet (e.g., MARKER) - return as-is for special handling
                return Ok(packet);
            }

            // Get payload (everything after the 8-byte header)
            let payload = &packet[PACKET_HEADER_SIZE..];

            if payload.len() < 2 {
                return Err(Error::Protocol("DATA packet payload too small".to_string()));
            }

            // Read data flags (first 2 bytes of payload)
            let data_flags_value = u16::from_be_bytes([payload[0], payload[1]]);

            // Check for end of response - Python checks both flags and message type
            let has_end_flag = (data_flags_value & data_flags::END_OF_RESPONSE) != 0;
            let has_eof_flag = (data_flags_value & data_flags::EOF) != 0;

            // Also check for EndOfResponse message type (header + 3 bytes with msg type 29)
            let has_end_message =
                payload.len() == 3 && payload[2] == MessageType::EndOfResponse as u8;

            // Accumulate payload first
            if is_first_packet {
                // First packet: include data flags in accumulated payload
                extend_bounded(
                    &mut accumulated_payload,
                    payload,
                    self.wire_limits.max_response_bytes,
                )?;
                is_first_packet = false;
            } else {
                // Subsequent packets: skip the data flags, append only the message data
                extend_bounded(
                    &mut accumulated_payload,
                    &payload[2..],
                    self.wire_limits.max_response_bytes,
                )?;
            }

            // Check for end of response using data flags from this packet
            let is_end_of_response = has_end_flag || has_eof_flag || has_end_message;

            // If data flags don't indicate end, scan the ACCUMULATED message data
            // for terminal messages. We scan accumulated data (not just current packet)
            // because messages can span packet boundaries.
            let has_terminal_message = if !is_end_of_response && accumulated_payload.len() > 2 {
                self.scan_for_terminal_message(&accumulated_payload[2..])
            } else {
                false
            };

            // Check if this is the last packet
            if is_end_of_response || has_terminal_message {
                break;
            }
        }

        // Build a synthetic packet with combined payload
        let total_len = PACKET_HEADER_SIZE + accumulated_payload.len();
        let mut result = Vec::with_capacity(total_len);

        // Build header
        if self.large_sdu {
            result.extend_from_slice(&(total_len as u32).to_be_bytes());
        } else {
            result.extend_from_slice(&(total_len as u16).to_be_bytes());
            result.extend_from_slice(&[0, 0]); // Checksum
        }
        result.push(PacketType::Data as u8);
        result.push(0); // Flags
        result.extend_from_slice(&[0, 0]); // Header checksum

        // Add combined payload
        result.extend_from_slice(&accumulated_payload);

        Ok(bytes::Bytes::from(result))
    }

    fn append_data_payload(&self, target: &mut Vec<u8>, packet: &[u8]) -> Result<()> {
        if packet.len() < PACKET_HEADER_SIZE + 2 {
            return Err(Error::Protocol("DATA packet payload too small".to_string()));
        }
        if packet[4] != PacketType::Data as u8 {
            return Err(Error::InvalidPacketType(packet[4]));
        }
        let payload = &packet[PACKET_HEADER_SIZE..];
        let bytes = if target.is_empty() {
            payload
        } else {
            &payload[2..]
        };
        extend_bounded(target, bytes, self.wire_limits.max_response_bytes)
    }

    /// Scan message data for terminal message types (ERROR or END_OF_RESPONSE)
    /// that indicate the response is complete.
    ///
    /// This is needed because Oracle doesn't always set the END_OF_RESPONSE flag
    /// in the data flags for LOB operations. Instead, we must detect the terminal
    /// message by parsing the message stream.
    ///
    /// NOTE: This is conservative - it only returns true if we can definitively
    /// identify a terminal message. We avoid false positives by not scanning
    /// raw byte values (which could match message type values by coincidence).
    fn scan_for_terminal_message(&self, data: &[u8]) -> bool {
        use crate::buffer::ReadBuffer;
        use crate::constants::MessageType;

        if data.is_empty() {
            return false;
        }

        // Try to parse the message stream and look for ERROR or END_OF_RESPONSE
        let mut buf = ReadBuffer::from_slice(data);

        while buf.remaining() > 0 {
            let msg_type = match buf.read_u8() {
                Ok(t) => t,
                Err(_) => return false, // Can't read, assume incomplete
            };

            // END_OF_RESPONSE is a standalone message with no additional data
            if msg_type == MessageType::EndOfResponse as u8 {
                return true;
            }

            // ERROR message indicates end of response for older Oracle
            if msg_type == MessageType::Error as u8 {
                // Error message found - this indicates end of response
                return true;
            }

            // STATUS message also indicates end of response
            if msg_type == MessageType::Status as u8 {
                return true;
            }

            // TOKEN identifies the request whose response follows. It has a UB8 payload and is
            // not itself terminal; validation happens in the operation-specific parser.
            if msg_type == MessageType::Token as u8 {
                if buf.read_ub8().is_err() {
                    return false;
                }
                continue;
            }

            // LOB_DATA message - skip the data
            if msg_type == MessageType::LobData as u8 {
                // Read length-prefixed data and skip it
                match buf.read_raw_bytes_chunked() {
                    Ok(_) => continue,
                    Err(_) => return false, // Incomplete LOB data, need more packets
                }
            }

            // PARAMETER message (8) - this contains the updated locator and amount.
            // For LOB write responses, PARAMETER is the first message and the response
            // is relatively small (locator + error info). We can safely scan for
            // ERROR/END_OF_RESPONSE bytes because the locator doesn't contain arbitrary
            // binary data that would false-positive.
            //
            // For LOB read responses, LobData comes first and contains the actual data,
            // which might contain bytes that match ERROR (4) or END_OF_RESPONSE (29).
            // But since we skip LobData content, by the time we reach PARAMETER,
            // the remaining data is just locator + error info.
            if msg_type == MessageType::Parameter as u8 {
                let remaining = buf.remaining_bytes();
                // Check if ERROR (4) or END_OF_RESPONSE (29) appears in remaining bytes
                // This is safe because PARAMETER data (locator + amount) doesn't contain
                // arbitrary binary data that would false-positive.
                if remaining.contains(&(MessageType::Error as u8))
                    || remaining.contains(&(MessageType::EndOfResponse as u8))
                {
                    return true;
                }
                // If no terminal marker found, response might be incomplete
                return false;
            }

            // For other unknown message types, we can't determine the end
            return false;
        }

        false
    }

    /// Send a marker packet with the specified marker type
    async fn send_marker(&mut self, marker_type: u8) -> Result<()> {
        let mut buf = WriteBuffer::with_capacity(16);

        // Build marker packet header
        // Marker packet structure: [length][0x00][0x00][0x00][0x0c][flags][0x00][0x00] + payload
        // Payload: [0x01][0x00][marker_type]
        let payload_len = 3; // 0x01, 0x00, marker_type
        let total_len = (PACKET_HEADER_SIZE + payload_len) as u16;

        // Header
        buf.write_u16_be(total_len)?;
        buf.write_u16_be(0)?; // zeros in large_sdu position
        buf.write_u8(PacketType::Marker as u8)?;
        buf.write_u8(0)?; // flags
        buf.write_u16_be(0)?; // reserved

        // Payload
        buf.write_u8(0x01)?; // constant
        buf.write_u8(0x00)?; // constant
        buf.write_u8(marker_type)?;

        self.send(buf.as_slice()).await
    }

    /// Handle the reset protocol after receiving a MARKER packet
    /// This sends a reset marker, waits for the reset response, then returns the error packet
    /// Returns Err if the connection is closed after reset (some Oracle versions do this)
    async fn handle_marker_reset(&mut self) -> Result<bytes::Bytes> {
        const MARKER_TYPE_RESET: u8 = 2;

        // Send reset marker
        self.send_marker(MARKER_TYPE_RESET).await?;

        // Read packets until we get a reset marker back
        loop {
            let packet = self.receive().await?;
            if packet.len() < PACKET_HEADER_SIZE {
                return Err(Error::Protocol("Invalid packet received".to_string()));
            }

            let packet_type = packet[4];

            if packet_type == PacketType::Marker as u8 {
                // Check if it's a reset marker
                if packet.len() >= PACKET_HEADER_SIZE + 3 {
                    let marker_type = packet[PACKET_HEADER_SIZE + 2];
                    if marker_type == MARKER_TYPE_RESET {
                        break;
                    }
                }
            } else {
                // Non-marker packet received unexpectedly during reset wait
                return Ok(packet);
            }
        }

        // Try to read the error packet (may need to skip additional marker packets first)
        // Note: Some Oracle versions (like Oracle Free) may close the connection after reset
        // instead of sending an error packet
        loop {
            match self.receive().await {
                Ok(packet) => {
                    let packet_type = packet[4];

                    if packet_type != PacketType::Marker as u8 {
                        // This should be the error data packet
                        return Ok(packet);
                    }
                    // Skip additional marker packets
                }
                Err(_) => {
                    // Connection closed after reset - Oracle Free and some versions
                    // close the connection instead of sending the error details.
                    // This typically happens when:
                    // - Table or view doesn't exist
                    // - Insufficient privileges to access the object
                    // - Invalid SQL syntax
                    return Err(Error::ConnectionClosedByServer(
                        "Query failed - Oracle closed the connection without providing error details. \
                         This typically indicates insufficient privileges or the object doesn't exist.".to_string()
                    ));
                }
            }
        }
    }
}

/// An Oracle database connection.
///
/// This is the main type for interacting with Oracle databases. It provides
/// methods for executing queries, DML statements, PL/SQL blocks, and managing
/// transactions.
///
/// Connections are created using [`Connection::connect`] or
/// [`Connection::connect_with_config`]. For connection pooling, use the
/// `deadpool-oracle` crate.
///
/// # Example
///
/// ```rust,no_run
/// use oracle_rs::{Config, Connection, Value};
///
/// # async fn example() -> oracle_rs::Result<()> {
/// // Create a connection
/// let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password");
/// let conn = Connection::connect_with_config(config).await?;
///
/// // Execute a query
/// let result = conn.query("SELECT * FROM employees WHERE dept_id = :1", &[10.into()]).await?;
/// for row in &result.rows {
///     let name = row.get_by_name("name").and_then(|v| v.as_str()).unwrap_or("");
///     println!("Employee: {}", name);
/// }
///
/// // Execute DML with transaction
/// conn.execute("INSERT INTO logs (msg) VALUES (:1)", &["Hello".into()]).await?;
/// conn.commit().await?;
///
/// // Close the connection
/// conn.close().await?;
/// # Ok(())
/// # }
/// ```
///
/// # Thread Safety
///
/// `Connection` is `Send` and `Sync`, but operations are serialized internally
/// via a mutex. For parallel query execution, use multiple connections (e.g.,
/// via a connection pool).
pub struct Connection {
    inner: Arc<Mutex<ConnectionInner>>,
    config: Config,
    closed: AtomicBool,
    id: u32,
}

// Connection ID counter
static CONNECTION_ID_COUNTER: AtomicU32 = AtomicU32::new(1);

impl Connection {
    /// Create a new connection to an Oracle database
    ///
    /// # Arguments
    ///
    /// * `connect_string` - Connection string in EZConnect format (e.g., "host:port/service")
    /// * `username` - Database username
    /// * `password` - Database password
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let conn = Connection::connect("localhost:1521/ORCLPDB1", "scott", "tiger").await?;
    /// ```
    pub async fn connect(connect_string: &str, username: &str, password: &str) -> Result<Self> {
        let mut config: Config = connect_string.parse()?;
        config.username = username.to_string();
        config.set_password(password);
        Self::connect_with_config(config).await
    }

    /// Create a new connection using a [`Config`].
    ///
    /// This is the preferred way to create connections as it gives full control
    /// over connection parameters including TLS, timeouts, and statement caching.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use oracle_rs::{Config, Connection};
    ///
    /// # async fn example() -> oracle_rs::Result<()> {
    /// let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password")
    ///     .with_statement_cache_size(50);
    ///
    /// let conn = Connection::connect_with_config(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn connect_with_config(config: Config) -> Result<Self> {
        config.wire_limits.validate()?;
        let id = CONNECTION_ID_COUNTER.fetch_add(1, Ordering::Relaxed);

        // Create TCP connection
        let tcp_stream = tokio::time::timeout(
            config.connect_timeout,
            connect_tcp(&config.host, config.port),
        )
        .await
        .map_err(|_| Error::ConnectionTimeout(config.connect_timeout))??;

        // Set TCP options
        tcp_stream.set_nodelay(true)?;

        // Wrap with TLS if configured
        let stream = if config.is_tls_enabled() {
            let tls_config = config
                .tls_config
                .as_ref()
                .cloned()
                .unwrap_or_else(TlsConfig::new);

            let tls_stream = connect_tls(tcp_stream, &config.host, &tls_config).await?;
            OracleStream::Tls(tls_stream)
        } else {
            OracleStream::Plain(tcp_stream)
        };

        let mut inner = ConnectionInner::new_with_cache(config.stmtcachesize, config.wire_limits);
        inner.stream = Some(stream);
        inner.state = ConnectionState::Connected;

        let mut conn = Connection {
            inner: Arc::new(Mutex::new(inner)),
            config,
            closed: AtomicBool::new(false),
            id,
        };

        // Perform connection handshake
        conn.perform_handshake().await?;
        conn.config.clear_password();

        Ok(conn)
    }

    /// Get the connection ID
    pub fn id(&self) -> u32 {
        self.id
    }

    /// Check if the connection is closed
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    /// Mark the connection as closed
    ///
    /// This should be called when the underlying connection is detected as broken.
    /// Once marked closed, `is_closed()` returns true and operations will fail fast.
    pub fn mark_closed(&self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    /// Immediately terminate the transport without sending protocol logoff.
    ///
    /// This is the cancellation boundary used by dbx-rs. Dropping the stream causes Oracle to
    /// clean up the session and any active operation; server-side cleanup still requires live
    /// verification before certification.
    pub async fn abort(&self) {
        self.closed.store(true, Ordering::Relaxed);
        let mut inner = self.inner.lock().await;
        inner.state = ConnectionState::Closed;
        inner.stream.take();
    }

    /// Helper to mark connection as closed if the result is a connection error
    fn handle_result<T>(&self, result: Result<T>) -> Result<T> {
        if let Err(ref e) = result {
            if e.is_connection_error() {
                self.mark_closed();
            }
        }
        result
    }

    /// Get server information
    pub async fn server_info(&self) -> ServerInfo {
        let inner = self.inner.lock().await;
        inner.server_info.clone()
    }

    /// Get the current connection state
    pub async fn state(&self) -> ConnectionState {
        let inner = self.inner.lock().await;
        inner.state
    }

    /// Perform the connection handshake
    async fn perform_handshake(&self) -> Result<()> {
        // Step 1: Send CONNECT packet and parse ACCEPT response
        self.send_connect_packet().await?;

        // Step 2: OOB check (required for protocol version >= 318 AND server supports OOB)
        // Both conditions must be met - server must have indicated OOB support in ACCEPT
        let needs_oob_check = {
            let inner = self.inner.lock().await;
            !self.config.is_tls_enabled()
                && inner.server_info.protocol_version >= crate::constants::version::MIN_OOB_CHECK
                && inner.server_info.supports_oob
        };
        if needs_oob_check {
            self.send_oob_check().await?;
        }

        // Step 3: Protocol negotiation
        self.negotiate_protocol().await?;

        // Step 4: Data types negotiation
        self.negotiate_data_types().await?;

        // Step 5: Authentication
        self.authenticate().await?;

        Ok(())
    }

    /// Send OOB (Out of Band) check
    /// Required for protocol version >= 318
    async fn send_oob_check(&self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Step 1: Send raw byte "!" (0x21) for OOB check
        inner.send(&[0x21]).await?;

        // Step 2: Send MARKER packet with Reset
        let marker_payload = [1u8, 0u8, crate::constants::MarkerType::Reset as u8];
        let mut packet_buf = WriteBuffer::new();

        if large_sdu {
            packet_buf.write_u32_be((PACKET_HEADER_SIZE + marker_payload.len()) as u32)?;
        } else {
            packet_buf.write_u16_be((PACKET_HEADER_SIZE + marker_payload.len()) as u16)?;
            packet_buf.write_u16_be(0)?; // Checksum
        }
        packet_buf.write_u8(PacketType::Marker as u8)?;
        packet_buf.write_u8(0)?; // Flags
        packet_buf.write_u16_be(0)?; // Header checksum
        packet_buf.write_bytes(&marker_payload)?;

        inner.send(&packet_buf.freeze()).await?;

        // Step 3: Wait for OOB reset response
        // The server sends back a MARKER packet or reset acknowledgment
        let response = inner.receive().await?;

        // Validate response - should be a MARKER packet type (12)
        if response.len() > 4 && response[4] == PacketType::Marker as u8 {
            Ok(())
        } else {
            // Server might just acknowledge without a specific packet
            // This is acceptable in some Oracle versions
            Ok(())
        }
    }

    /// Send the initial CONNECT packet
    async fn send_connect_packet(&self) -> Result<()> {
        let mut inner = self.inner.lock().await;

        // Build connect packet using ConnectMessage for proper packet format
        let connect_msg = ConnectMessage::from_config(&self.config);
        let (connect_packet, continuation) = connect_msg.build_with_continuation()?;

        // Send the CONNECT packet
        inner.send(&connect_packet).await?;

        // If we have a continuation DATA packet (for large connect strings), send it
        if let Some(ref data_packet) = continuation {
            inner.send(data_packet).await?;
        }

        const MAX_RESENDS: u8 = 3;
        let mut resend_count: u8 = 0;

        loop {
            // Wait for response
            let response = inner.receive().await?;

            // Parse response packet type
            if response.len() < PACKET_HEADER_SIZE {
                return Err(Error::PacketTooShort {
                    expected: PACKET_HEADER_SIZE,
                    actual: response.len(),
                });
            }

            let packet_type = response[4];

            match packet_type {
                2 => {
                    // ACCEPT - parse the accept message to get protocol version and capabilities
                    let packet = Packet::from_bytes(response)?;
                    let accept = AcceptMessage::parse(&packet)?;

                    // Set large_sdu mode if protocol version >= 315
                    inner.large_sdu = accept.uses_large_sdu();

                    // Update server info
                    inner.server_info.protocol_version = accept.protocol_version;
                    inner.server_info.supports_oob = accept.supports_oob;
                    inner.sdu_size = accept.sdu.min(65535) as u16;

                    inner.state = ConnectionState::Connected;
                    return Ok(());
                }
                4 => {
                    // REFUSE
                    let mut buf = ReadBuffer::new(response.slice(PACKET_HEADER_SIZE..));
                    let _reason = buf.read_u8()?;
                    let _user_reason = buf.read_u8()?;

                    return Err(Error::ConnectionRefused {
                        error_code: None,
                        message: Some("Connection refused by server".to_string()),
                    });
                }
                5 => {
                    // REDIRECT
                    return Err(Error::ConnectionRedirect(
                        "redirect not implemented".to_string(),
                    ));
                }
                11 => {
                    // RESEND - server requests retransmission of the connect packet
                    resend_count += 1;
                    if resend_count > MAX_RESENDS {
                        return Err(Error::ProtocolError(
                            "Server requested too many resends during connect".to_string(),
                        ));
                    }
                    if connect_resend_action(self.config.is_tls_enabled(), response[5])?
                        == ConnectResendAction::RenegotiateTls
                    {
                        self.renegotiate_tls_transport(&mut inner).await?;
                    }
                    inner.send(&connect_packet).await?;
                    if let Some(ref data_packet) = continuation {
                        inner.send(data_packet).await?;
                    }
                }
                _ => {
                    return Err(Error::ProtocolError(format!(
                        "Unexpected packet type during connect: {}",
                        packet_type,
                    )));
                }
            }
        }
    }

    async fn renegotiate_tls_transport(&self, inner: &mut ConnectionInner) -> Result<()> {
        let stream = inner.stream.take().ok_or(Error::ConnectionClosed)?;
        let tcp_stream = match stream {
            OracleStream::Tls(stream) => stream.into_tcp_stream(),
            stream @ OracleStream::Plain(_) => {
                inner.stream = Some(stream);
                return Err(Error::ProtocolError(
                    "TLS renegotiation requested without an active TLS stream".to_string(),
                ));
            }
        };
        let tls_config = self
            .config
            .tls_config
            .as_ref()
            .cloned()
            .unwrap_or_else(TlsConfig::new);

        match connect_tls(tcp_stream, &self.config.host, &tls_config).await {
            Ok(stream) => {
                inner.stream = Some(OracleStream::Tls(stream));
                Ok(())
            }
            Err(error) => {
                inner.state = ConnectionState::Closed;
                Err(error)
            }
        }
    }

    /// Negotiate protocol version and capabilities
    async fn negotiate_protocol(&self) -> Result<()> {
        use crate::messages::ProtocolMessage;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Build protocol request (includes header)
        let protocol_msg = ProtocolMessage::new();
        let packet = protocol_msg.build_request(large_sdu)?;
        inner.send(&packet).await?;

        // Receive response
        let response = inner.receive().await?;

        // Validate packet type (at offset 4 for both SDU modes)
        if response.len() <= 4 || response[4] != PacketType::Data as u8 {
            return Err(Error::ProtocolError(
                "Protocol negotiation failed".to_string(),
            ));
        }

        // Parse the Protocol response to extract server capabilities
        // The payload starts after the 8-byte header
        let payload = &response[PACKET_HEADER_SIZE..];
        let mut protocol_msg = ProtocolMessage::new();
        protocol_msg.parse_response(payload, &mut inner.capabilities)?;
        inner.capabilities.check_text_encodings()?;

        // Update server info with banner
        if let Some(banner) = &protocol_msg.server_banner {
            inner.server_info.version = database_version_from_banner(banner).unwrap_or_default();
            inner.server_info.banner = banner.clone();
        }

        inner.state = ConnectionState::ProtocolNegotiated;
        Ok(())
    }

    /// Negotiate data types
    async fn negotiate_data_types(&self) -> Result<()> {
        use crate::messages::DataTypesMessage;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Build data types request using DataTypesMessage (includes all ~320 data types)
        let data_types_msg = DataTypesMessage::new();
        let packet = data_types_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&packet).await?;

        // Receive response
        let response = inner.receive().await?;

        // Basic validation - packet type is at offset 4 regardless of large_sdu
        if response.len() > 4 && response[4] == PacketType::Data as u8 {
            inner.state = ConnectionState::DataTypesNegotiated;
            Ok(())
        } else {
            Err(Error::ProtocolError(
                "Data types negotiation failed".to_string(),
            ))
        }
    }

    /// Perform authentication
    async fn authenticate(&self) -> Result<()> {
        let service_name = match &self.config.service {
            ServiceMethod::ServiceName(name) => name.clone(),
            ServiceMethod::Sid(sid) => sid.clone(),
        };

        let mut auth =
            AuthMessage::new(&self.config.username, self.config.password(), &service_name);

        // Phase one: send username and session info
        {
            let mut inner = self.inner.lock().await;
            let large_sdu = inner.large_sdu;
            let request = auth.build_request(&inner.capabilities, large_sdu)?;
            inner.send(&request).await?;

            let response = inner.receive().await?;
            if response.len() <= PACKET_HEADER_SIZE {
                return Err(Error::Protocol("Empty auth response".to_string()));
            }

            // Check for error message type
            if response.len() > PACKET_HEADER_SIZE + 2 {
                let msg_type = response[PACKET_HEADER_SIZE + 2];
                if msg_type == MessageType::Error as u8 {
                    return Err(Error::AuthenticationFailed(
                        "Server rejected authentication phase one".to_string(),
                    ));
                }
            }

            auth.parse_response(
                &response[PACKET_HEADER_SIZE..],
                inner.capabilities.ttc_field_version,
            )?;
        }

        // Phase two: send encrypted password
        if auth.phase() == AuthPhase::Two {
            let mut inner = self.inner.lock().await;
            let large_sdu = inner.large_sdu;
            let request = auth.build_request(&inner.capabilities, large_sdu)?;
            inner.send(&request).await?;

            let response = inner.receive().await?;
            if response.len() <= PACKET_HEADER_SIZE {
                return Err(Error::Protocol("Empty auth phase two response".to_string()));
            }

            // Check for error message type or marker
            let packet_type = response[4];
            if packet_type == 12 {
                // Marker - authentication failed
                return Err(Error::AuthenticationFailed(
                    "Server sent MARKER - authentication rejected".to_string(),
                ));
            }

            if response.len() > PACKET_HEADER_SIZE + 2 {
                let msg_type = response[PACKET_HEADER_SIZE + 2];
                if msg_type == MessageType::Error as u8 {
                    return Err(Error::InvalidCredentials);
                }
            }

            auth.parse_response(
                &response[PACKET_HEADER_SIZE..],
                inner.capabilities.ttc_field_version,
            )?;
        }

        // Verify authentication completed
        if !auth.is_complete() {
            return Err(Error::AuthenticationFailed(
                "Authentication did not complete".to_string(),
            ));
        }

        // Store combo key for later use (encrypted data)
        let mut inner = self.inner.lock().await;
        if let Some(combo_key) = auth.combo_key() {
            inner.capabilities.combo_key = Some(combo_key.to_vec());
        }
        if let Some(version) = auth.database_version(inner.capabilities.ttc_field_version) {
            inner.server_info.version = version;
        }
        if let Some(identity) = auth.session_identity() {
            inner.server_info.session_id = identity.session_id;
            inner.server_info.serial_number = u32::from(identity.serial_number);
        }
        // Auth used sequence numbers 1 and 2, set to 2 so next is 3
        inner.sequence_number = 2;
        inner.state = ConnectionState::Ready;

        Ok(())
    }

    /// Execute a SQL statement and return the result
    ///
    /// # Arguments
    ///
    /// * `sql` - SQL statement to execute
    /// * `params` - Bind parameters (use `Value::Integer`, `Value::String`, etc.)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use oracle_rs::Value;
    ///
    /// // Query with bind parameters
    /// let result = conn.execute(
    ///     "SELECT * FROM employees WHERE department_id = :1",
    ///     &[Value::Integer(10)]
    /// ).await?;
    ///
    /// // DML with bind parameters
    /// let result = conn.execute(
    ///     "UPDATE employees SET salary = :1 WHERE employee_id = :2",
    ///     &[Value::Integer(50000), Value::Integer(100)]
    /// ).await?;
    /// println!("Rows affected: {}", result.rows_affected);
    /// ```
    pub async fn execute(&self, sql: &str, params: &[Value]) -> Result<QueryResult> {
        self.ensure_ready().await?;

        // Check statement cache for existing prepared statement
        let (statement, from_cache) = {
            let mut inner = self.inner.lock().await;
            if let Some(ref mut cache) = inner.statement_cache {
                if let Some(cached_stmt) = cache.get(sql) {
                    (cached_stmt, true)
                } else {
                    (Statement::new(sql), false)
                }
            } else {
                (Statement::new(sql), false)
            }
        };

        let result = match statement.statement_type() {
            StatementType::Query => {
                self.execute_query_with_params(&statement, params, 100)
                    .await
            }
            _ => self.execute_dml_with_params(&statement, params).await,
        };

        // Return statement to cache or cache it for the first time
        match &result {
            Ok(query_result) => {
                let mut inner = self.inner.lock().await;
                if let Some(ref mut cache) = inner.statement_cache {
                    let should_close_cursor = if statement.statement_type() == StatementType::Query
                    {
                        !query_result.has_more_rows
                    } else {
                        true // DML/DDL/PL-SQL: always close
                    };

                    if from_cache {
                        cache.return_statement(sql);
                        if should_close_cursor {
                            cache.mark_cursor_closed(sql);
                        }
                    } else if query_result.cursor_id > 0 && !statement.is_ddl() {
                        let mut stmt_to_cache = statement.clone();
                        stmt_to_cache.set_cursor_id(query_result.cursor_id);
                        stmt_to_cache.set_executed(true);
                        cache.put(sql.to_string(), stmt_to_cache);
                        if should_close_cursor {
                            cache.mark_cursor_closed(sql);
                        }
                    }
                }
            }
            Err(_) => {
                if from_cache {
                    let mut inner = self.inner.lock().await;
                    if let Some(ref mut cache) = inner.statement_cache {
                        cache.return_statement(sql);
                        cache.mark_cursor_closed(sql);
                    }
                }
            }
        }

        result
    }

    /// Execute a query and return rows
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use oracle_rs::Value;
    ///
    /// let result = conn.query(
    ///     "SELECT * FROM employees WHERE salary > :1",
    ///     &[Value::Integer(50000)]
    /// ).await?;
    /// ```
    pub async fn query(&self, sql: &str, params: &[Value]) -> Result<QueryResult> {
        self.query_with_fetch_size(sql, params, 100).await
    }

    /// Execute a query with a bounded initial fetch page.
    pub async fn query_with_fetch_size(
        &self,
        sql: &str,
        params: &[Value],
        fetch_size: u32,
    ) -> Result<QueryResult> {
        if fetch_size == 0 || fetch_size as usize > self.config.wire_limits.max_rows_per_response {
            return Err(Error::InvalidLimits);
        }
        self.ensure_ready().await?;

        // Check statement cache for existing prepared statement
        let (statement, from_cache) = {
            let mut inner = self.inner.lock().await;
            if let Some(ref mut cache) = inner.statement_cache {
                if let Some(cached_stmt) = cache.get(sql) {
                    (cached_stmt, true)
                } else {
                    (Statement::new(sql), false)
                }
            } else {
                (Statement::new(sql), false)
            }
        };

        // If using cached statement, save the columns (Oracle won't resend on reexecute)
        let cached_columns = if from_cache {
            Some(statement.columns().to_vec())
        } else {
            None
        };

        let mut result = self
            .execute_query_with_params(&statement, params, fetch_size)
            .await;

        // For cached statements, restore columns if Oracle didn't send them
        if let (Ok(ref mut query_result), Some(columns)) = (&mut result, cached_columns) {
            if query_result.columns.is_empty() && !columns.is_empty() {
                query_result.columns = columns;
            }
        }

        // Return statement to cache or cache it for the first time
        match &result {
            Ok(query_result) => {
                let mut inner = self.inner.lock().await;
                if let Some(ref mut cache) = inner.statement_cache {
                    if from_cache {
                        cache.return_statement(sql);
                        if !query_result.has_more_rows {
                            cache.mark_cursor_closed(sql);
                        }
                    } else if query_result.cursor_id > 0 && !statement.is_ddl() {
                        let mut stmt_to_cache = statement.clone();
                        stmt_to_cache.set_cursor_id(query_result.cursor_id);
                        stmt_to_cache.set_executed(true);
                        stmt_to_cache.set_columns(query_result.columns.clone());
                        cache.put(sql.to_string(), stmt_to_cache);
                        if !query_result.has_more_rows {
                            cache.mark_cursor_closed(sql);
                        }
                    }
                }
            }
            Err(_) => {
                if from_cache {
                    let mut inner = self.inner.lock().await;
                    if let Some(ref mut cache) = inner.statement_cache {
                        cache.return_statement(sql);
                        cache.mark_cursor_closed(sql);
                    }
                }
            }
        }

        self.handle_result(result)
    }

    /// Parse and describe a query without fetching rows.
    pub async fn describe(&self, sql: &str) -> Result<Vec<ColumnInfo>> {
        self.ensure_ready().await?;
        let statement = Statement::new(sql);
        if !statement.is_query() {
            return Err(Error::SqlError(
                "describe requires a query statement".to_string(),
            ));
        }

        let mut message = ExecuteMessage::new(&statement, ExecuteOptions::describe_only());
        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let sequence_number = inner.next_sequence_number();
        message.set_sequence_number(sequence_number);
        let request = message.build_request_with_sdu(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;
        let result = self.receive_query_result(&mut inner, &[]).await?;
        Ok(result.columns)
    }

    /// Execute DML (INSERT, UPDATE, DELETE) and return rows affected
    pub async fn execute_dml_sql(&self, sql: &str, params: &[Value]) -> Result<u64> {
        self.ensure_ready().await?;

        // Check statement cache for existing prepared statement
        let (statement, from_cache) = {
            let mut inner = self.inner.lock().await;
            if let Some(ref mut cache) = inner.statement_cache {
                if let Some(cached_stmt) = cache.get(sql) {
                    (cached_stmt, true)
                } else {
                    (Statement::new(sql), false)
                }
            } else {
                (Statement::new(sql), false)
            }
        };

        let result = self.execute_dml_with_params(&statement, params).await;

        // Return statement to cache or cache it for the first time
        // DML cursors are always closed after execution (no fetch phase)
        match &result {
            Ok(query_result) => {
                let mut inner = self.inner.lock().await;
                if let Some(ref mut cache) = inner.statement_cache {
                    if from_cache {
                        cache.return_statement(sql);
                        cache.mark_cursor_closed(sql);
                    } else if query_result.cursor_id > 0 && !statement.is_ddl() {
                        let mut stmt_to_cache = statement.clone();
                        stmt_to_cache.set_cursor_id(query_result.cursor_id);
                        stmt_to_cache.set_executed(true);
                        cache.put(sql.to_string(), stmt_to_cache);
                        cache.mark_cursor_closed(sql);
                    }
                }
            }
            Err(_) => {
                if from_cache {
                    let mut inner = self.inner.lock().await;
                    if let Some(ref mut cache) = inner.statement_cache {
                        cache.return_statement(sql);
                        cache.mark_cursor_closed(sql);
                    }
                }
            }
        }

        self.handle_result(result).map(|r| r.rows_affected)
    }

    /// Execute a PL/SQL block with IN/OUT/INOUT parameters
    ///
    /// This method allows execution of PL/SQL anonymous blocks or procedure calls
    /// that have OUT or IN OUT parameters. The `params` slice specifies the direction
    /// and type of each bind parameter.
    ///
    /// # Arguments
    ///
    /// * `sql` - The PL/SQL block or procedure call
    /// * `params` - The bind parameters with direction information
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use oracle_rs::{Connection, BindParam, OracleType, Value};
    ///
    /// // Call a procedure with IN and OUT parameters
    /// let result = conn.execute_plsql(
    ///     "BEGIN get_employee_name(:1, :2); END;",
    ///     &[
    ///         BindParam::input(Value::Integer(100)),           // IN: employee_id
    ///         BindParam::output(OracleType::Varchar, 100),     // OUT: employee_name
    ///     ]
    /// ).await?;
    ///
    /// // Get the OUT parameter value
    /// let name = result.get_string(0).unwrap_or("Unknown");
    /// println!("Employee name: {}", name);
    /// ```
    ///
    /// # REF CURSOR Example
    ///
    /// ```rust,ignore
    /// use oracle_rs::{Connection, BindParam, Value};
    ///
    /// // Call a procedure that returns a REF CURSOR
    /// let result = conn.execute_plsql(
    ///     "BEGIN OPEN :1 FOR SELECT * FROM employees; END;",
    ///     &[BindParam::output_cursor()]
    /// ).await?;
    ///
    /// // Get the cursor ID and fetch rows
    /// if let Some(cursor_id) = result.get_cursor_id(0) {
    ///     let rows = conn.fetch_cursor(cursor_id, 100).await?;
    ///     for row in rows {
    ///         println!("{:?}", row);
    ///     }
    /// }
    /// ```
    pub async fn execute_plsql(&self, sql: &str, params: &[BindParam]) -> Result<PlsqlResult> {
        self.ensure_ready().await?;

        let statement = Statement::new(sql);

        // Build values for bind parameters
        // IN params: use provided value or Null
        // OUT params: use placeholder value (required for metadata, server ignores actual value)
        // INOUT params: use provided value or Null
        let bind_values: Vec<Value> = params
            .iter()
            .map(|p| {
                if p.direction == BindDirection::Output {
                    // OUT params get a placeholder based on their type
                    // Oracle still needs a value sent in the request (even though it's ignored)
                    p.placeholder_value()
                } else {
                    // IN and INOUT params use the provided value or Null
                    p.value.clone().unwrap_or(Value::Null)
                }
            })
            .collect();

        // Build bind metadata for proper buffer sizes
        // For OUTPUT params, use the user-specified buffer_size
        // For INPUT params, derive buffer_size from the actual value
        let bind_metadata: Vec<crate::messages::BindMetadata> = params
            .iter()
            .zip(bind_values.iter())
            .map(|(p, v)| {
                let buffer_size = if p.buffer_size > 0 {
                    p.buffer_size
                } else {
                    // Derive from value
                    match v {
                        Value::String(s) => std::cmp::max(s.len() as u32, 1),
                        Value::Bytes(b) => std::cmp::max(b.len() as u32, 1),
                        Value::Integer(_) | Value::Number(_) => 22, // Oracle NUMBER max size
                        Value::Float(_) => 8,                       // BINARY_DOUBLE
                        Value::Boolean(_) => 1,
                        Value::Timestamp(_) => 13,
                        Value::Date(_) => 7,
                        Value::RowId(_) => 18,
                        _ => 100, // Default fallback
                    }
                };
                crate::messages::BindMetadata {
                    oracle_type: p.oracle_type,
                    buffer_size,
                }
            })
            .collect();

        // Create execute message with PL/SQL options
        let options = ExecuteOptions::for_plsql();
        let mut execute_msg = ExecuteMessage::new(&statement, options);
        execute_msg.set_bind_values(bind_values);
        execute_msg.set_bind_metadata(bind_metadata);

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let seq_num = inner.next_sequence_number();
        execute_msg.set_sequence_number(seq_num);
        let request = execute_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive response
        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty PL/SQL response".to_string()));
        }

        // Check for MARKER packet (indicates error - requires reset protocol)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            // Handle marker reset protocol and get the error packet
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            // Parse error response to extract the actual Oracle error
            let _: QueryResult =
                self.parse_error_response(payload, inner.capabilities.ttc_field_version)?;
            return Err(Error::Protocol("PL/SQL execution failed".to_string()));
        }

        // Parse the PL/SQL response
        let payload = &response[PACKET_HEADER_SIZE..];
        let caps = inner.capabilities.clone();
        drop(inner); // Release lock before parsing

        self.parse_plsql_response(payload, &caps, params)
    }

    /// Execute a batch of DML statements with multiple rows of bind values
    ///
    /// This method efficiently executes the same SQL statement multiple times
    /// with different bind values (executemany pattern).
    ///
    /// # Arguments
    ///
    /// * `batch` - The batch containing SQL and rows of bind values
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use oracle_rs::{Connection, BatchBuilder, Value};
    ///
    /// let batch = BatchBuilder::new("INSERT INTO users (id, name) VALUES (:1, :2)")
    ///     .add_row(vec![Value::Integer(1), Value::String("Alice".to_string())])
    ///     .add_row(vec![Value::Integer(2), Value::String("Bob".to_string())])
    ///     .with_row_counts()
    ///     .build();
    ///
    /// let result = conn.execute_batch(&batch).await?;
    /// println!("Total rows affected: {}", result.total_rows_affected);
    /// ```
    pub async fn execute_batch(&self, batch: &BatchBinds) -> Result<BatchResult> {
        self.ensure_ready().await?;

        // Validate the batch
        batch.validate()?;

        if batch.rows.is_empty() {
            return Ok(BatchResult::new());
        }

        // Build execute options for batch DML
        let mut options = ExecuteOptions::for_dml(batch.options.auto_commit);
        options.num_execs = batch.rows.len() as u32;
        options.batch_errors = batch.options.batch_errors;
        options.dml_row_counts = batch.options.array_dml_row_counts;

        // Create execute message with batch bind values
        let mut execute_msg = ExecuteMessage::new(&batch.statement, options);
        execute_msg.set_batch_bind_values(batch.rows.clone());

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let seq_num = inner.next_sequence_number();
        execute_msg.set_sequence_number(seq_num);
        let request = execute_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive response
        let mut response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty batch response".to_string()));
        }

        // Check packet type - handle MARKER packets
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            // Handle BREAK/RESET protocol same as regular DML
            response = self.handle_marker_protocol(&mut inner, response).await?;
        }

        // Parse the batch response
        let payload = &response[PACKET_HEADER_SIZE..];
        let ttc_field_version = inner.capabilities.ttc_field_version;
        drop(inner); // Release lock before parsing

        self.parse_batch_response(
            payload,
            batch.rows.len(),
            batch.options.array_dml_row_counts,
            ttc_field_version,
        )
    }

    /// Handle MARKER packet protocol (BREAK/RESET)
    async fn handle_marker_protocol(
        &self,
        inner: &mut ConnectionInner,
        initial_response: Bytes,
    ) -> Result<Bytes> {
        // Extract marker type from packet
        let marker_type = if initial_response.len() >= PACKET_HEADER_SIZE + 3 {
            initial_response[PACKET_HEADER_SIZE + 2]
        } else {
            1 // Assume BREAK
        };

        if marker_type == 1 {
            // BREAK marker - send RESET and wait for response
            self.send_marker(inner, 2).await?;

            // Wait for RESET marker back
            loop {
                match inner.receive().await {
                    Ok(pkt) => {
                        if pkt.len() < PACKET_HEADER_SIZE + 1 {
                            break;
                        }
                        let pkt_type = pkt[4];
                        if pkt_type == PacketType::Marker as u8 {
                            if pkt.len() >= PACKET_HEADER_SIZE + 3 {
                                let mk_type = pkt[PACKET_HEADER_SIZE + 2];
                                if mk_type == 2 {
                                    // Got RESET marker, break out
                                    break;
                                }
                            }
                        } else if pkt_type == PacketType::Data as u8 {
                            // Got DATA packet - return it as the response
                            return Ok(pkt);
                        } else {
                            break;
                        }
                    }
                    Err(e) => {
                        inner.state = ConnectionState::Closed;
                        return Err(e);
                    }
                }
            }

            // After RESET, continue receiving until we get DATA packet
            loop {
                match inner.receive().await {
                    Ok(pkt) => {
                        let pkt_type = pkt[4];
                        if pkt_type == PacketType::Marker as u8 {
                            continue;
                        } else if pkt_type == PacketType::Data as u8 {
                            return Ok(pkt);
                        } else {
                            return Err(Error::Protocol(format!(
                                "Unexpected packet type {} after reset",
                                pkt_type
                            )));
                        }
                    }
                    Err(e) => {
                        inner.state = ConnectionState::Closed;
                        return Err(e);
                    }
                }
            }
        }

        Ok(initial_response)
    }

    /// Parse batch execution response
    fn parse_batch_response(
        &self,
        payload: &[u8],
        batch_size: usize,
        want_row_counts: bool,
        ttc_field_version: u8,
    ) -> Result<BatchResult> {
        if payload.len() < 3 {
            return Err(Error::Protocol("Batch response too short".to_string()));
        }

        let mut buf = ReadBuffer::from_slice(payload);

        // Skip data flags
        buf.skip(2)?;

        let mut rows_affected: u64 = 0;
        let mut row_counts: Option<Vec<u64>> = None;
        let mut end_of_response = false;

        // Process messages until end_of_response or out of data
        while !end_of_response && buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                x if x == MessageType::Token as u8 => {
                    validate_response_token(&mut buf, NON_PIPELINED_TOKEN_NUMBER)?;
                }

                // Error (4) - may contain error or success info
                x if x == MessageType::Error as u8 => {
                    let (error_code, error_msg, _cid, row_count) = self
                        .parse_error_info_with_rowcount_for_version(&mut buf, ttc_field_version)?;
                    rows_affected = row_count;
                    if error_code != 0 && error_code != 1403 {
                        return Err(Error::OracleError {
                            code: error_code,
                            message: error_msg.unwrap_or_default(),
                        });
                    }
                }

                // Parameter (8) - return parameters (may contain row counts)
                x if x == MessageType::Parameter as u8 => {
                    if let Some(counts) =
                        self.parse_return_parameters_internal(&mut buf, want_row_counts)?
                    {
                        row_counts = Some(counts);
                    }
                }

                // Status (9) - call status
                x if x == MessageType::Status as u8 => {
                    let _call_status = buf.read_ub4()?;
                    let _end_to_end_seq = buf.read_ub2()?;
                }

                // BitVector (21)
                21 => {
                    let _num_columns_sent = buf.read_ub2()?;
                    if buf.remaining() > 0 {
                        let _byte = buf.read_u8()?;
                    }
                }

                // End of Response (29) - explicit end marker
                29 => {
                    end_of_response = true;
                }

                _ => {
                    // Unknown message type - continue processing
                }
            }
        }

        let mut result = BatchResult::new();
        result.total_rows_affected = rows_affected;
        result.success_count = batch_size;
        result.row_counts = row_counts;

        Ok(result)
    }

    /// Fetch more rows from an open cursor
    ///
    /// This method is used when a query result has `has_more_rows == true`
    /// to retrieve additional rows from the server.
    ///
    /// # Arguments
    ///
    /// * `cursor_id` - The cursor ID from a previous query result
    /// * `columns` - Column information from the original query
    /// * `fetch_size` - Number of rows to fetch
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut result = conn.query("SELECT * FROM large_table", &[]).await?;
    /// let mut all_rows = result.rows.clone();
    ///
    /// while result.has_more_rows {
    ///     result = conn.fetch_more(result.cursor_id, &result.columns, 100).await?;
    ///     all_rows.extend(result.rows);
    /// }
    /// ```
    pub async fn fetch_more(
        &self,
        cursor_id: u16,
        columns: &[ColumnInfo],
        fetch_size: u32,
    ) -> Result<QueryResult> {
        self.fetch_more_with_previous_row(cursor_id, columns, None, fetch_size)
            .await
    }

    /// Fetch more rows while retaining the final row from the previous fetch page.
    ///
    /// Oracle may omit values that are identical to the preceding row, including the first row
    /// of a continuation page. Callers that fetch a cursor page-by-page must provide that row so
    /// the omission can be reconstructed without substituting a value.
    pub async fn fetch_more_with_previous_row(
        &self,
        cursor_id: u16,
        columns: &[ColumnInfo],
        previous_row: Option<&Row>,
        fetch_size: u32,
    ) -> Result<QueryResult> {
        if fetch_size == 0 || fetch_size as usize > self.config.wire_limits.max_rows_per_response {
            return Err(Error::InvalidLimits);
        }
        self.ensure_ready().await?;

        // Build fetch message
        let mut fetch_msg = FetchMessage::new(cursor_id, fetch_size);

        let mut inner = self.inner.lock().await;
        fetch_msg.set_sequence_number(inner.next_sequence_number());
        let request = fetch_msg.build_request_with_sdu(&inner.capabilities, inner.large_sdu)?;
        inner.send(&request).await?;

        self.receive_query_result_with_previous(&mut inner, columns, previous_row)
            .await
    }

    /// Fetch rows from a REF CURSOR
    ///
    /// This method fetches rows from a REF CURSOR that was returned from a
    /// PL/SQL procedure or function. The cursor contains the column metadata
    /// and cursor ID needed to fetch the rows.
    ///
    /// # Arguments
    ///
    /// * `cursor` - The REF CURSOR returned from PL/SQL
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use oracle_rs::{Connection, BindParam, Value};
    ///
    /// // Call a procedure that returns a REF CURSOR
    /// let result = conn.execute_plsql(
    ///     "BEGIN OPEN :1 FOR SELECT id, name FROM employees; END;",
    ///     &[BindParam::output_cursor()]
    /// ).await?;
    ///
    /// // Get the cursor and fetch rows
    /// if let Value::Cursor(cursor) = &result.out_values[0] {
    ///     let rows = conn.fetch_cursor(cursor).await?;
    ///     println!("Fetched {} rows", rows.row_count());
    ///     for row in &rows.rows {
    ///         println!("{:?}", row);
    ///     }
    /// }
    /// ```
    pub async fn fetch_cursor(&self, cursor: &crate::types::RefCursor) -> Result<QueryResult> {
        self.fetch_cursor_with_size(cursor, 100).await
    }

    /// Fetch rows from a REF CURSOR with a specified fetch size
    ///
    /// This is the same as `fetch_cursor` but allows specifying how many
    /// rows to fetch at once.
    ///
    /// REF CURSORs use an ExecuteMessage with only the FETCH option because
    /// the cursor is already open from the PL/SQL execution. The cursor_id
    /// and column metadata were obtained when the REF CURSOR was returned.
    ///
    /// # Arguments
    ///
    /// * `cursor` - The REF CURSOR returned from PL/SQL
    /// * `fetch_size` - Number of rows to fetch (default is 100)
    pub async fn fetch_cursor_with_size(
        &self,
        cursor: &crate::types::RefCursor,
        fetch_size: u32,
    ) -> Result<QueryResult> {
        use crate::messages::ExecuteMessage;

        if cursor.cursor_id() == 0 {
            return Err(Error::InvalidCursor(
                "Cursor ID is 0 (not initialized)".to_string(),
            ));
        }

        self.ensure_ready().await?;

        // REF CURSOR uses ExecuteMessage with FETCH only (no SQL, no EXECUTE)
        // Create a statement with the cursor's metadata
        let mut stmt = Statement::new(""); // No SQL for REF CURSOR
        stmt.set_cursor_id(cursor.cursor_id());
        stmt.set_columns(cursor.columns().to_vec());
        stmt.set_executed(true); // Already executed by Oracle
        stmt.set_statement_type(crate::statement::StatementType::Query); // This is a query cursor

        // Build execute message with only FETCH option
        let options = crate::messages::ExecuteOptions::for_ref_cursor(fetch_size);
        let mut execute_msg = ExecuteMessage::new(&stmt, options);

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let seq_num = inner.next_sequence_number();
        execute_msg.set_sequence_number(seq_num);

        let request = execute_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        self.receive_query_result(&mut inner, cursor.columns())
            .await
    }

    /// Fetch rows from an implicit result set
    ///
    /// Implicit results are returned via `DBMS_SQL.RETURN_RESULT` from PL/SQL.
    /// They contain cursor metadata but no rows until fetched.
    ///
    /// # Arguments
    ///
    /// * `result` - The implicit result from PL/SQL execution
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let plsql_result = conn.execute_plsql(r#"
    ///     declare
    ///         c sys_refcursor;
    ///     begin
    ///         open c for select * from employees;
    ///         dbms_sql.return_result(c);
    ///     end;
    /// "#, &[]).await?;
    ///
    /// for implicit in plsql_result.implicit_results.iter() {
    ///     let rows = conn.fetch_implicit_result(implicit).await?;
    ///     println!("Fetched {} rows", rows.row_count());
    /// }
    /// ```
    pub async fn fetch_implicit_result(&self, result: &ImplicitResult) -> Result<QueryResult> {
        self.fetch_implicit_result_with_size(result, 100).await
    }

    /// Fetch rows from an implicit result set with a specified fetch size
    pub async fn fetch_implicit_result_with_size(
        &self,
        result: &ImplicitResult,
        fetch_size: u32,
    ) -> Result<QueryResult> {
        // Convert implicit result to RefCursor and use fetch_cursor mechanism
        let cursor = crate::types::RefCursor::new(result.cursor_id, result.columns.clone());
        self.fetch_cursor_with_size(&cursor, fetch_size).await
    }

    /// Parse fetch response to extract additional rows
    ///
    /// REF CURSOR fetch responses contain a series of messages:
    /// - RowHeader (6): Contains metadata about the following row data
    /// - RowData (7): Contains the actual row values
    /// - Error (4): Contains error info with cursor_id and row counts
    #[allow(dead_code)]
    fn parse_fetch_response(
        &self,
        payload: &[u8],
        columns: &[ColumnInfo],
        caps: &Capabilities,
    ) -> Result<QueryResult> {
        if payload.len() < 3 {
            return Err(Error::Protocol("Fetch response too short".to_string()));
        }

        let mut buf = ReadBuffer::from_slice(payload);
        let mut rows = Vec::new();
        let mut has_more_rows = false;

        // Bit vector for duplicate column optimization
        let mut bit_vector: Option<Vec<u8>> = None;
        let mut previous_row_values: Option<Vec<Value>> = None;

        // Skip data flags
        buf.skip(2)?;

        // Process multiple messages in the response
        while buf.remaining() >= 1 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                x if x == MessageType::Token as u8 => {
                    validate_response_token(&mut buf, NON_PIPELINED_TOKEN_NUMBER)?;
                }
                x if x == MessageType::RowHeader as u8 => {
                    // Skip row header metadata (per Python's _process_row_header)
                    buf.skip(1)?; // flags
                    buf.skip_ub2()?; // num requests
                    buf.skip_ub4()?; // iteration number
                    buf.skip_ub4()?; // num iters
                    buf.skip_ub2()?; // buffer length
                    let num_bytes = buf.read_ub4()?;
                    if num_bytes > 0 {
                        buf.skip(1)?; // skip repeated length
                                      // This bit vector in row header is for the following row data
                        let bv = buf.read_bytes_vec(num_bytes as usize)?;
                        bit_vector = Some(bv);
                    }
                    let rxhrid_bytes = buf.read_ub4()?;
                    if rxhrid_bytes > 0 {
                        buf.skip_raw_bytes_chunked()?;
                    }
                }
                x if x == MessageType::RowData as u8 => {
                    // Parse actual row data with bit vector support
                    let row = self.parse_row_data_with_bitvector(
                        &mut buf,
                        columns,
                        caps,
                        bit_vector.as_deref(),
                        previous_row_values.as_ref(),
                    )?;
                    previous_row_values = Some(row.values().to_vec());
                    bit_vector = None;
                    rows.push(row);
                }
                x if x == MessageType::BitVector as u8 => {
                    // BitVector indicates which columns have actual data vs duplicates
                    let _num_columns_sent = buf.read_ub2()?;
                    let num_bytes = (columns.len() + 7) / 8; // Round up
                    if num_bytes > 0 {
                        let bv = buf.read_bytes_vec(num_bytes)?;
                        bit_vector = Some(bv);
                    }
                    // Continue processing - RowData follows
                }
                x if x == MessageType::Error as u8 => {
                    // Error message contains row count and cursor info
                    let (error_code, error_msg, more_rows) =
                        self.parse_error_message_info(&mut buf)?;
                    has_more_rows = more_rows;
                    if error_code != 0 && error_code != 1403 {
                        // 1403 = no data found
                        return Err(Error::OracleError {
                            code: error_code,
                            message: error_msg,
                        });
                    }
                    break; // Error message marks end of response
                }
                x if x == MessageType::Status as u8 => {
                    // Status message - usually marks end
                    break;
                }
                x if x == MessageType::EndOfResponse as u8 => {
                    break;
                }
                _ => {
                    // Unknown message type - stop processing
                    break;
                }
            }
        }

        Ok(QueryResult {
            columns: columns.to_vec(),
            rows,
            rows_affected: 0,
            has_more_rows,
            cursor_id: 0,
            response_packet_count: 0,
        })
    }

    /// Parse error message info including cursor_id and row counts
    #[allow(dead_code)]
    fn parse_error_message_info(&self, buf: &mut ReadBuffer) -> Result<(u32, String, bool)> {
        let _call_status = buf.read_ub4()?; // end of call status
        buf.skip_ub2()?; // end to end seq#
        buf.skip_ub4()?; // current row number
        buf.skip_ub2()?; // error number
        buf.skip_ub2()?; // array elem error
        buf.skip_ub2()?; // array elem error
        let _cursor_id = buf.read_ub2()?; // cursor id
        let _error_pos = buf.read_sb2()?; // error position
        buf.skip(1)?; // sql type
        buf.skip(1)?; // fatal?
        buf.skip(1)?; // flags
        buf.skip(1)?; // user cursor options
        buf.skip(1)?; // UPI parameter
        let flags = buf.read_u8()?; // flags
                                    // Skip rowid - fixed 10 bytes in Oracle format
        buf.skip(10)?; // rowid is 10 bytes
        buf.skip_ub4()?; // OS error
        buf.skip(1)?; // statement number
        buf.skip(1)?; // call number
        buf.skip_ub2()?; // padding
        buf.skip_ub4()?; // success iters
        let num_bytes = buf.read_ub4()?; // oerrdd
        if num_bytes > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // Skip batch error codes
        let num_errors = buf.read_ub2()?;
        if num_errors > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // Skip batch error offsets
        let num_offsets = buf.read_ub4()?;
        if num_offsets > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // Skip batch error messages
        let temp16 = buf.read_ub2()?;
        if temp16 > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // Read extended error info
        let error_num = buf.read_ub4()?;
        let row_count = buf.read_ub8()?;
        let more_rows = row_count > 0 || (flags & 0x20) != 0;

        // Read error message if present
        let error_msg = if error_num != 0 {
            buf.read_string_with_length()?.unwrap_or_default()
        } else {
            String::new()
        };

        Ok((error_num, error_msg, more_rows))
    }

    /// Open a scrollable cursor for bidirectional navigation
    ///
    /// Scrollable cursors allow moving forward and backward through result sets,
    /// jumping to specific positions, and fetching from various locations.
    ///
    /// # Arguments
    ///
    /// * `sql` - SQL query to execute
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let mut cursor = conn.open_scrollable_cursor("SELECT * FROM employees").await?;
    ///
    /// // Move to different positions
    /// let first = conn.scroll(&mut cursor, FetchOrientation::First, 0).await?;
    /// let last = conn.scroll(&mut cursor, FetchOrientation::Last, 0).await?;
    /// let row5 = conn.scroll(&mut cursor, FetchOrientation::Absolute, 5).await?;
    ///
    /// conn.close_cursor(&mut cursor).await?;
    /// ```
    pub async fn open_scrollable_cursor(&self, sql: &str) -> Result<ScrollableCursor> {
        self.ensure_ready().await?;

        let statement = Statement::new(sql);

        // For scrollable cursors, execute with scrollable flag and prefetch 1 row
        // to get column metadata. The scroll() method will fetch actual rows at
        // specific positions.
        let mut options = ExecuteOptions::for_query(1); // prefetch 1 row for column info

        options.scrollable = true;

        let mut execute_msg = ExecuteMessage::new(&statement, options);

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let seq_num = inner.next_sequence_number();
        execute_msg.set_sequence_number(seq_num);
        let request = execute_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response
        let response = inner.receive().await?;

        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol(
                "Empty scrollable cursor response".to_string(),
            ));
        }

        // Check for MARKER packet (indicates error - requires reset protocol)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            // Handle marker reset protocol and get the error packet
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            // Parse error response to extract the actual Oracle error
            let _: QueryResult =
                self.parse_error_response(payload, inner.capabilities.ttc_field_version)?;
            // If we get here without error, something unexpected happened
            return Err(Error::Protocol(
                "Unexpected successful response after MARKER".to_string(),
            ));
        }

        // Parse describe info to get columns
        let payload = &response[PACKET_HEADER_SIZE..];
        let result = self.parse_query_response(payload, &inner.capabilities)?;

        Ok(ScrollableCursor::new(result.cursor_id, result.columns))
    }

    /// Scroll to a position in a scrollable cursor and fetch rows
    ///
    /// # Arguments
    ///
    /// * `cursor` - The scrollable cursor to scroll
    /// * `orientation` - The direction/mode of scrolling
    /// * `offset` - Position offset (used for Absolute and Relative modes)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Go to first row
    /// let first = conn.scroll(&mut cursor, FetchOrientation::First, 0).await?;
    ///
    /// // Go to absolute position 10
    /// let row10 = conn.scroll(&mut cursor, FetchOrientation::Absolute, 10).await?;
    ///
    /// // Move 5 rows forward from current position
    /// let plus5 = conn.scroll(&mut cursor, FetchOrientation::Relative, 5).await?;
    ///
    /// // Move 3 rows backward
    /// let minus3 = conn.scroll(&mut cursor, FetchOrientation::Relative, -3).await?;
    /// ```
    pub async fn scroll(
        &self,
        cursor: &mut ScrollableCursor,
        orientation: FetchOrientation,
        offset: i64,
    ) -> Result<ScrollResult> {
        self.ensure_ready().await?;

        if !cursor.is_open() {
            return Err(Error::CursorClosed);
        }

        // Create a statement for the scroll operation (uses the existing cursor)
        let mut stmt = Statement::new("");
        stmt.set_cursor_id(cursor.cursor_id);
        stmt.set_columns(cursor.columns.clone());
        stmt.set_executed(true);
        stmt.set_statement_type(crate::statement::StatementType::Query);

        // Build execute message with scroll_operation=true
        let mut options = ExecuteOptions::for_query(1);
        options.scrollable = true;
        options.scroll_operation = true;
        options.fetch_orientation = orientation as u32;
        // Calculate fetch_pos based on orientation
        options.fetch_pos = match orientation {
            FetchOrientation::First => 1,
            FetchOrientation::Last => 0, // Server calculates
            FetchOrientation::Absolute => offset.max(0) as u32,
            FetchOrientation::Relative => (cursor.position + offset).max(0) as u32,
            FetchOrientation::Next => (cursor.position + 1).max(0) as u32,
            FetchOrientation::Prior => (cursor.position - 1).max(0) as u32,
            FetchOrientation::Current => cursor.position.max(0) as u32,
        };

        let mut execute_msg = ExecuteMessage::new(&stmt, options);

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let seq_num = inner.next_sequence_number();
        execute_msg.set_sequence_number(seq_num);
        let request = execute_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response
        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty scroll response".to_string()));
        }

        // Check for MARKER packet
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let _: QueryResult =
                self.parse_error_response(payload, inner.capabilities.ttc_field_version)?;
            return Err(Error::Protocol("Scroll operation failed".to_string()));
        }

        let payload = &response[PACKET_HEADER_SIZE..];
        // Use cursor's columns since Oracle doesn't re-send column metadata for scroll operations
        let query_result =
            self.parse_query_response_with_columns(payload, &inner.capabilities, &cursor.columns)?;

        // Use position from Oracle's response (rows_affected contains the row position)
        // For scrollable cursors, Oracle returns the row number in error_info.rowcount
        let new_position = if !query_result.rows.is_empty() {
            // Position is the actual row number from Oracle
            query_result.rows_affected as i64
        } else {
            // No rows returned - calculate position based on orientation
            match orientation {
                FetchOrientation::First => 0, // Before first
                FetchOrientation::Last => cursor.row_count.unwrap_or(0) as i64 + 1, // After last
                FetchOrientation::Next => cursor.position + 1,
                FetchOrientation::Prior => cursor.position - 1,
                FetchOrientation::Absolute => offset,
                FetchOrientation::Relative => cursor.position + offset,
                FetchOrientation::Current => cursor.position,
            }
        };

        cursor.update_position(new_position);

        let mut result = ScrollResult::new(query_result.rows, new_position);
        result.at_end = !query_result.has_more_rows;
        result.at_beginning = new_position <= 1;

        Ok(result)
    }

    /// Close a scrollable cursor
    ///
    /// # Arguments
    ///
    /// * `cursor` - The scrollable cursor to close
    pub async fn close_cursor(&self, cursor: &mut ScrollableCursor) -> Result<()> {
        if !cursor.is_open() {
            return Ok(());
        }

        // Send close cursor message
        // For now, just mark it as closed - the cursor will be cleaned up
        // when the connection is closed or reused
        cursor.mark_closed();
        Ok(())
    }

    /// Get type information for a database object or collection type
    ///
    /// This method queries Oracle's data dictionary to retrieve type metadata
    /// for collections (VARRAY, Nested Table) and user-defined object types.
    ///
    /// # Arguments
    ///
    /// * `type_name` - Fully qualified type name (e.g., "SCHEMA.TYPE_NAME" or just "TYPE_NAME")
    ///
    /// # Returns
    ///
    /// A `DbObjectType` containing the type metadata, including:
    /// - Schema and type name
    /// - Whether it's a collection
    /// - Collection type (VARRAY, Nested Table, etc.)
    /// - Element type for collections
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let number_array = conn.get_type("MY_NUMBER_ARRAY").await?;
    /// assert!(number_array.is_collection);
    /// ```
    pub async fn get_type(&self, type_name: &str) -> Result<crate::dbobject::DbObjectType> {
        use crate::dbobject::{CollectionType, DbObjectType};

        self.ensure_ready().await?;

        // Parse type name into schema and name
        let (schema, name) = parse_type_name(type_name, &self.config.username);

        // First, query ALL_TYPES to get basic type info
        let type_info = self
            .query(
                "SELECT typecode, type_oid FROM all_types WHERE owner = :1 AND type_name = :2",
                &[Value::String(schema.clone()), Value::String(name.clone())],
            )
            .await?;

        if type_info.rows.is_empty() {
            return Err(Error::OracleError {
                code: 4043, // ORA-04043: object does not exist
                message: format!("Type {}.{} not found", schema, name),
            });
        }

        let row = &type_info.rows[0];
        let typecode = row.get(0).and_then(|v| v.as_str()).unwrap_or("");
        let type_oid = row.get(1).and_then(|v| v.as_bytes()).map(|b| b.to_vec());

        // Check if it's a collection
        if typecode == "COLLECTION" {
            // Query ALL_COLL_TYPES for collection details
            let coll_info = self.query(
                "SELECT coll_type, elem_type_name, elem_type_owner, upper_bound FROM all_coll_types WHERE owner = :1 AND type_name = :2",
                &[Value::String(schema.clone()), Value::String(name.clone())],
            ).await?;

            if coll_info.rows.is_empty() {
                return Err(Error::OracleError {
                    code: 4043,
                    message: format!("Collection type {}.{} metadata not found", schema, name),
                });
            }

            let coll_row = &coll_info.rows[0];
            let coll_type_str = coll_row.get(0).and_then(|v| v.as_str()).unwrap_or("");
            let elem_type_name = coll_row
                .get(1)
                .and_then(|v| v.as_str())
                .unwrap_or("VARCHAR2");
            let _elem_type_owner = coll_row.get(2).and_then(|v| v.as_str());

            let collection_type = match coll_type_str {
                "VARYING ARRAY" => CollectionType::Varray,
                "TABLE" => CollectionType::NestedTable,
                _ => CollectionType::Varray, // Default
            };

            let element_type = oracle_type_from_name(elem_type_name);

            let mut obj_type =
                DbObjectType::collection(schema, name, collection_type, element_type);
            obj_type.oid = type_oid;
            Ok(obj_type)
        } else {
            // Regular object type (not yet fully implemented)
            let mut obj_type = DbObjectType::new(schema, name);
            obj_type.oid = type_oid;
            Ok(obj_type)
        }
    }

    /// Internal: Execute a query statement with optional bind parameters
    async fn execute_query_with_params(
        &self,
        statement: &Statement,
        params: &[Value],
        prefetch_rows: u32,
    ) -> Result<QueryResult> {
        // For first execution, check if we might have LOBs (no prefetch for safety)
        // This can be optimized later with describe-only first
        let options = ExecuteOptions::for_query(prefetch_rows);
        let mut execute_msg = ExecuteMessage::new(statement, options);

        // Set bind values if provided
        if !params.is_empty() {
            execute_msg.set_bind_values(params.to_vec());
        }

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let seq_num = inner.next_sequence_number();
        execute_msg.set_sequence_number(seq_num);
        let request = execute_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        let mut result = self.receive_query_result(&mut inner, &[]).await?;

        // Check if any columns are LOB types that require defines
        let has_lob_columns = result.columns.iter().any(|col| col.is_lob());

        if has_lob_columns && !statement.requires_define() {
            // We need to re-execute with column defines
            // Create a modified statement with the define flag set
            let mut stmt_with_define = statement.clone();
            stmt_with_define.set_columns(result.columns.clone());
            stmt_with_define.set_cursor_id(result.cursor_id);
            stmt_with_define.set_requires_define(true);
            stmt_with_define.set_no_prefetch(true);
            stmt_with_define.set_executed(true);

            // Re-execute with defines
            let define_options = ExecuteOptions::for_query(prefetch_rows);
            let mut define_msg = ExecuteMessage::new(&stmt_with_define, define_options);
            let seq_num = inner.next_sequence_number();
            define_msg.set_sequence_number(seq_num);

            let define_request =
                define_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;
            inner.send(&define_request).await?;

            result = self
                .receive_query_result(&mut inner, stmt_with_define.columns())
                .await?;
        }

        Ok(result)
    }

    async fn receive_query_result(
        &self,
        inner: &mut ConnectionInner,
        known_columns: &[ColumnInfo],
    ) -> Result<QueryResult> {
        self.receive_query_result_with_previous(inner, known_columns, None)
            .await
    }

    async fn receive_query_result_with_previous(
        &self,
        inner: &mut ConnectionInner,
        known_columns: &[ColumnInfo],
        previous_row: Option<&Row>,
    ) -> Result<QueryResult> {
        let mut payload = Vec::new();
        let mut packet_count = 0_usize;
        loop {
            let packet = inner.receive().await?;
            packet_count = increment_response_packet_count(packet_count)?;
            if packet.len() <= PACKET_HEADER_SIZE {
                return Err(Error::Protocol("Empty query response".to_string()));
            }
            if packet[4] == PacketType::Marker as u8 {
                let error_response = inner.handle_marker_reset().await?;
                let error_payload = &error_response[PACKET_HEADER_SIZE..];
                return self
                    .parse_error_response(error_payload, inner.capabilities.ttc_field_version);
            }
            inner.append_data_payload(&mut payload, &packet)?;
            match self.parse_query_response_with_columns_and_previous(
                &payload,
                &inner.capabilities,
                known_columns,
                previous_row.map(Row::values),
            ) {
                Ok(mut result) => {
                    result.response_packet_count = packet_count;
                    return Ok(result);
                }
                Err(Error::BufferUnderflow { .. } | Error::IncompleteResponse) => {}
                Err(error) => return Err(error),
            }
        }
    }

    /// Internal: Execute a DML statement with optional bind parameters
    async fn execute_dml_with_params(
        &self,
        statement: &Statement,
        params: &[Value],
    ) -> Result<QueryResult> {
        let options = ExecuteOptions::for_dml(false); // Don't auto-commit
        let mut execute_msg = ExecuteMessage::new(statement, options);

        // Set bind values if provided
        if !params.is_empty() {
            execute_msg.set_bind_values(params.to_vec());
        }

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let ttc_field_version = inner.capabilities.ttc_field_version;
        let seq_num = inner.next_sequence_number();
        execute_msg.set_sequence_number(seq_num);
        let request = execute_msg.build_request_with_sdu(&inner.capabilities, large_sdu)?;

        inner.send(&request).await?;

        // Receive response
        let mut response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty DML response".to_string()));
        }

        // Check packet type - handle MARKER packets
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            // Need to do reset protocol and then get the actual response
            // Extract marker type from packet: after header (8 bytes) + data flags (2 bytes) + marker type (1 byte)
            let marker_type = if response.len() >= PACKET_HEADER_SIZE + 3 {
                response[PACKET_HEADER_SIZE + 2]
            } else {
                1 // Assume BREAK
            };

            if marker_type == 1 {
                // BREAK marker - send RESET and wait for response
                self.send_marker(&mut inner, 2).await?;

                // Wait for RESET marker back or DATA packet with error
                // The server may send: RESET marker, or BREAK marker followed by DATA, or just close
                let mut got_reset = false;
                let mut max_attempts = 5;
                loop {
                    match inner.receive().await {
                        Ok(pkt) => {
                            if pkt.len() < PACKET_HEADER_SIZE + 1 {
                                break;
                            }
                            let pkt_type = pkt[4];
                            if pkt_type == PacketType::Marker as u8 {
                                if pkt.len() >= PACKET_HEADER_SIZE + 3 {
                                    let mk_type = pkt[PACKET_HEADER_SIZE + 2];
                                    if mk_type == 2 {
                                        // Got RESET marker, break out
                                        got_reset = true;
                                        break;
                                    }
                                    // Got another BREAK marker - server may be acknowledging
                                    // Keep trying a few times
                                    max_attempts -= 1;
                                    if max_attempts == 0 {
                                        // Give up and return a generic error
                                        return Err(Error::Protocol(
                                            "Server rejected operation (multiple BREAK markers)"
                                                .to_string(),
                                        ));
                                    }
                                    continue;
                                }
                            } else if pkt_type == PacketType::Data as u8 {
                                // Got DATA packet - use this as the response (may contain error)
                                let payload = &pkt[PACKET_HEADER_SIZE..];
                                return self.parse_dml_response(payload, ttc_field_version);
                            } else {
                                break;
                            }
                        }
                        Err(e) => {
                            // If we get EOF, the server may have closed the connection
                            // This can happen with temp LOB binding issues
                            inner.state = ConnectionState::Closed;
                            return Err(Error::Protocol(format!(
                                "Server closed connection during error handling: {}",
                                e
                            )));
                        }
                    }
                }

                // After RESET, try to receive DATA packet with error response
                // Note: Some Oracle servers "quit immediately" after reset without sending
                // an error packet. In that case, we'll get EOF which is handled below.
                if got_reset {
                    loop {
                        match inner.receive().await {
                            Ok(pkt) => {
                                if pkt.len() < PACKET_HEADER_SIZE + 1 {
                                    // Too short, connection may be closing
                                    break;
                                }
                                let pkt_type = pkt[4];
                                if pkt_type == PacketType::Marker as u8 {
                                    // More markers, keep reading
                                    continue;
                                } else if pkt_type == PacketType::Data as u8 {
                                    // Got DATA packet, use this as the response
                                    response = pkt;
                                    break;
                                } else {
                                    // Unknown packet type, return error
                                    return Err(Error::Protocol(format!(
                                        "Unexpected packet type {} after reset",
                                        pkt_type
                                    )));
                                }
                            }
                            Err(_e) => {
                                // EOF after reset is normal - server may close connection
                                // without sending error details. Return a descriptive error.
                                inner.state = ConnectionState::Closed;
                                return Err(Error::OracleError {
                                    code: 0,
                                    message: "Server rejected the operation and closed the connection. \
                                              This may happen when binding a temporary LOB to an INSERT statement. \
                                              Try using a different approach (e.g., DBMS_LOB procedures).".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        // Parse the response to extract rows affected (or error)
        let payload = &response[PACKET_HEADER_SIZE..];
        self.parse_dml_response(payload, ttc_field_version)
    }

    /// Parse query response to extract columns and rows
    ///
    /// Oracle sends multiple messages in a single response:
    /// - DescribeInfo (16): column metadata
    /// - RowHeader (6): row header info
    /// - RowData (7): actual column values
    /// - Error (4): completion status (may contain error or success)
    fn parse_query_response(&self, payload: &[u8], caps: &Capabilities) -> Result<QueryResult> {
        self.parse_query_response_with_columns(payload, caps, &[])
    }

    /// Parse query response with pre-known columns (for re-execute after define)
    fn parse_query_response_with_columns(
        &self,
        payload: &[u8],
        caps: &Capabilities,
        known_columns: &[ColumnInfo],
    ) -> Result<QueryResult> {
        self.parse_query_response_with_columns_and_previous(payload, caps, known_columns, None)
    }

    fn parse_query_response_with_columns_and_previous(
        &self,
        payload: &[u8],
        caps: &Capabilities,
        known_columns: &[ColumnInfo],
        seed_previous_row_values: Option<&[Value]>,
    ) -> Result<QueryResult> {
        if payload.len() < 3 {
            return Err(Error::IncompleteResponse);
        }

        let mut buf = ReadBuffer::from_slice(payload);

        // Skip data flags
        buf.skip(2)?;

        // Use known columns if provided, otherwise parse from describe info
        let mut columns: Vec<ColumnInfo> = known_columns.to_vec();
        let mut rows: Vec<Row> = Vec::new();
        let mut cursor_id: u16 = 0;
        let mut row_count: u64 = 0;
        let mut end_of_response = false;
        let mut has_more_rows = false;

        // Bit vector for duplicate column optimization
        // When Some, indicates which columns have actual data (bit=1) vs duplicates (bit=0)
        let mut bit_vector: Option<Vec<u8>> = None;
        // Previous row values for copying duplicates
        let mut previous_row_values = seed_previous_row_values.map(<[Value]>::to_vec);

        // Process messages until we hit end of response or run out of data
        while !end_of_response && buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                x if x == MessageType::Token as u8 => {
                    validate_response_token(&mut buf, NON_PIPELINED_TOKEN_NUMBER)?;
                }

                // DescribeInfo (16) - column metadata
                x if x == MessageType::DescribeInfo as u8 => {
                    // Skip chunked bytes first
                    buf.skip_raw_bytes_chunked()?;
                    columns = self.parse_describe_info(&mut buf, caps.ttc_field_version)?;
                }

                // RowHeader (6) - header info for rows
                x if x == MessageType::RowHeader as u8 => {
                    bit_vector = self.parse_row_header(&mut buf, columns.len())?;
                }

                // RowData (7) - actual row values
                x if x == MessageType::RowData as u8 => {
                    if rows.len() >= self.config.wire_limits.max_rows_per_response {
                        return Err(Error::LimitExceeded);
                    }
                    let row = self.parse_row_data_with_bitvector(
                        &mut buf,
                        &columns,
                        caps,
                        bit_vector.as_deref(),
                        previous_row_values.as_ref(),
                    )?;
                    // Store this row's values for potential duplicate copying
                    previous_row_values = Some(row.values().to_vec());
                    // Clear bit vector after using it (it's per-row)
                    bit_vector = None;
                    rows.push(row);
                }

                // Error (4) - completion or error
                x if x == MessageType::Error as u8 => {
                    let (error_code, error_msg, cid, rc) = self
                        .parse_error_info_with_rowcount_for_version(
                            &mut buf,
                            caps.ttc_field_version,
                        )?;
                    cursor_id = cid;
                    row_count = rc;
                    if error_code != 0 && error_code != 1403 {
                        // 1403 is "no data found" which is not an error for queries
                        return Err(Error::OracleError {
                            code: error_code,
                            message: error_msg.unwrap_or_default(),
                        });
                    }
                    has_more_rows = error_code == 0 && cursor_id != 0;
                    if !caps.supports_end_of_response {
                        end_of_response = true;
                    }
                }

                // Parameter (8) - return parameters
                x if x == MessageType::Parameter as u8 => {
                    self.parse_return_parameters(&mut buf)?;
                }

                // Status (9) - call status
                x if x == MessageType::Status as u8 => {
                    // Read call status and end-to-end seq number
                    let _call_status = buf.read_ub4()?;
                    let _end_to_end_seq = buf.read_ub2()?;
                    if !caps.supports_end_of_response {
                        end_of_response = true;
                    }
                }

                // BitVector (21) - column presence bitmap for sparse results
                // Bit=1 means actual data is sent, bit=0 means duplicate from previous row
                21 => {
                    // Read num columns sent
                    let _num_columns_sent = buf.read_ub2()?;
                    // Read bit vector (1 byte per 8 columns, rounded up)
                    let num_bytes = (columns.len() + 7) / 8;
                    if num_bytes > 0 {
                        let bv = buf.read_bytes_vec(num_bytes)?;
                        bit_vector = Some(bv);
                    }
                }

                x if x == MessageType::EndOfResponse as u8 => {
                    end_of_response = true;
                }

                _ => return Err(Error::InvalidMessageType(msg_type)),
            }
        }

        if !end_of_response {
            return Err(Error::IncompleteResponse);
        }

        Ok(QueryResult {
            columns,
            rows,
            rows_affected: row_count,
            has_more_rows,
            cursor_id,
            response_packet_count: 0,
        })
    }

    /// Parse a PL/SQL response containing OUT parameter values
    ///
    /// PL/SQL responses may contain:
    /// - IoVector (11): bind directions for each parameter
    /// - RowData (7): OUT parameter values
    /// - FlushOutBinds (19): signals end of OUT bind data
    /// - Error (4): completion status
    fn parse_plsql_response(
        &self,
        payload: &[u8],
        caps: &Capabilities,
        params: &[BindParam],
    ) -> Result<PlsqlResult> {
        if payload.len() < 3 {
            return Err(Error::Protocol("PL/SQL response too short".to_string()));
        }

        let mut buf = ReadBuffer::from_slice(payload);

        // Skip data flags
        buf.skip(2)?;

        let mut out_values: Vec<Value> = Vec::new();
        let mut _out_indices: Vec<usize> = Vec::new();
        let mut row_count: u64 = 0;
        let mut cursor_id: Option<u16> = None;
        let mut end_of_response = false;
        let mut implicit_results = ImplicitResults::new();

        // Create column infos for OUT params based on their oracle types
        let mut out_columns: Vec<ColumnInfo> = Vec::new();

        while !end_of_response && buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                x if x == MessageType::Token as u8 => {
                    validate_response_token(&mut buf, NON_PIPELINED_TOKEN_NUMBER)?;
                }

                // IoVector (11) - bind directions from server
                x if x == MessageType::IoVector as u8 => {
                    let (indices, cols) = self.parse_io_vector(&mut buf, params)?;
                    _out_indices = indices;
                    out_columns = cols;
                }

                // RowHeader (6)
                x if x == MessageType::RowHeader as u8 => {
                    let _ = self.parse_row_header(&mut buf, out_columns.len())?;
                }

                // RowData (7) - OUT parameter values
                x if x == MessageType::RowData as u8 => {
                    if !out_columns.is_empty() {
                        let row = self.parse_row_data_single(&mut buf, &out_columns, caps)?;
                        // Extract values from the row into out_values
                        for (idx, value) in row.into_values().into_iter().enumerate() {
                            // Check if this is a cursor
                            if let Value::Cursor(cursor) = &value {
                                if cursor_id.is_none() && cursor.cursor_id() != 0 {
                                    cursor_id = Some(cursor.cursor_id());
                                }
                            }
                            // Map back to original param position if we have indices
                            if idx < out_values.len() {
                                out_values[idx] = value;
                            } else {
                                out_values.push(value);
                            }
                        }
                    } else {
                        // Skip the row data if we don't have column info
                        // This shouldn't normally happen
                        break;
                    }
                }

                // DescribeInfo (16) - for REF CURSOR describe
                x if x == MessageType::DescribeInfo as u8 => {
                    buf.skip_raw_bytes_chunked()?;
                    let cursor_columns =
                        self.parse_describe_info(&mut buf, caps.ttc_field_version)?;
                    // Store cursor columns if needed
                    let _ = cursor_columns; // For now, just skip
                }

                // FlushOutBinds (19) - signals end of OUT bind data
                x if x == MessageType::FlushOutBinds as u8 => {
                    // This indicates that OUT bind data is done
                    // Just continue to get the error/completion status
                }

                // Error (4) - completion or error
                x if x == MessageType::Error as u8 => {
                    let (error_code, error_msg, _cid, rc) = self
                        .parse_error_info_with_rowcount_for_version(
                            &mut buf,
                            caps.ttc_field_version,
                        )?;
                    row_count = rc;
                    if error_code != 0 {
                        return Err(Error::OracleError {
                            code: error_code,
                            message: error_msg.unwrap_or_default(),
                        });
                    }
                    end_of_response = true;
                }

                // Parameter (8) - return parameters
                x if x == MessageType::Parameter as u8 => {
                    self.parse_return_parameters(&mut buf)?;
                }

                // Status (9)
                x if x == MessageType::Status as u8 => {
                    let _call_status = buf.read_ub4()?;
                    let _end_to_end_seq = buf.read_ub2()?;
                }

                // ImplicitResultset (27) - result sets from DBMS_SQL.RETURN_RESULT
                x if x == MessageType::ImplicitResultset as u8 => {
                    let parsed_results = self.parse_implicit_results(&mut buf, caps)?;
                    implicit_results = parsed_results;
                }

                _ => {
                    // Unknown message type - break to avoid parsing errors
                    break;
                }
            }
        }

        // If no IoVector was received, all params might be IN-only
        // In that case, out_values should be empty
        Ok(PlsqlResult {
            out_values,
            rows_affected: row_count,
            cursor_id,
            implicit_results,
        })
    }

    /// Parse implicit result sets from DBMS_SQL.RETURN_RESULT
    ///
    /// Format per Python base.pyx _process_implicit_result:
    /// - num_results: ub4 (number of implicit result sets)
    /// - For each result:
    ///   - num_bytes: ub1 + raw bytes (metadata to skip)
    ///   - describe_info: column metadata
    ///   - cursor_id: ub2
    fn parse_implicit_results(
        &self,
        buf: &mut ReadBuffer,
        caps: &Capabilities,
    ) -> Result<ImplicitResults> {
        let num_results = buf.read_ub4()?;
        let mut results = ImplicitResults::new();

        for _ in 0..num_results {
            // Skip metadata bytes
            let num_bytes = buf.read_u8()?;
            if num_bytes > 0 {
                buf.skip(num_bytes as usize)?;
            }

            // Parse column metadata for this result set
            let columns = self.parse_describe_info(buf, caps.ttc_field_version)?;

            // Read cursor ID
            let cursor_id = buf.read_ub2()?;

            // Create implicit result with metadata but no rows yet
            // Rows will be fetched separately using fetch_implicit_result
            let result = ImplicitResult::new(cursor_id, columns, Vec::new());
            results.add(result);
        }

        Ok(results)
    }

    /// Parse IO Vector message to get bind directions
    ///
    /// Returns a tuple of:
    /// - indices of OUT/INOUT parameters in the params list
    /// - column infos for parsing OUT values
    fn parse_io_vector(
        &self,
        buf: &mut ReadBuffer,
        params: &[BindParam],
    ) -> Result<(Vec<usize>, Vec<ColumnInfo>)> {
        // I/O vector format (from Python reference):
        // - skip 1 byte (flag)
        // - read ub2 (num requests)
        // - read ub4 (num iters)
        // - num_binds = num_iters * 256 + num_requests
        // - skip ub4 (num iters this time)
        // - skip ub2 (uac buffer length)
        // - read ub2 (num_bytes for bit vector), skip if > 0
        // - read ub2 (num_bytes for rowid), skip if > 0
        // - for each bind: read ub1 (bind_dir)

        buf.skip(1)?; // flag
        let num_requests = buf.read_ub2()? as u32;
        let num_iters = buf.read_ub4()?;
        let num_binds = num_iters * 256 + num_requests;
        let _ = buf.read_ub4()?; // num iters this time (discard)
        let _ = buf.read_ub2()?; // uac buffer length (discard)

        // Bit vector
        let num_bytes = buf.read_ub2()? as usize;
        if num_bytes > 0 {
            buf.skip(num_bytes)?;
        }

        // Rowid (raw bytes, not length-prefixed here)
        let num_bytes = buf.read_ub4()? as usize;
        if num_bytes > 0 {
            buf.skip_raw_bytes_chunked()?; // Skip rowid bytes using chunked read
        }

        // Read bind directions
        let mut out_indices = Vec::new();
        let mut out_columns = Vec::new();

        for i in 0..(num_binds as usize).min(params.len()) {
            let dir_byte = buf.read_u8()?;
            let dir = BindDirection::try_from(dir_byte).unwrap_or(BindDirection::Input);

            // If this is not an INPUT-only parameter, it has OUT data
            if dir != BindDirection::Input {
                out_indices.push(i);

                // Create a column info for parsing the OUT value
                let param = &params[i];
                let mut col = ColumnInfo::new(format!("OUT_{}", i), param.oracle_type);
                col.buffer_size = param.buffer_size;
                col.data_size = param.buffer_size;
                col.nullable = true;

                // For collection OUT params, extract element type from the placeholder
                if let Some(Value::Collection(ref placeholder)) = param.value {
                    if let Some(Value::Integer(elem_type_code)) = placeholder.get("_element_type") {
                        col.element_type =
                            crate::constants::OracleType::try_from(*elem_type_code as u8).ok();
                    }
                }

                out_columns.push(col);
            }
        }

        Ok((out_indices, out_columns))
    }

    /// Parse row header (TNS_MSG_TYPE_ROW_HEADER = 6)
    fn parse_row_header(
        &self,
        buf: &mut ReadBuffer,
        column_count: usize,
    ) -> Result<Option<Vec<u8>>> {
        buf.skip_ub1()?; // flags
        buf.skip_ub2()?; // num requests
        buf.skip_ub4()?; // iteration number
        buf.skip_ub4()?; // num iters
        buf.skip_ub2()?; // buffer length
        let num_bytes = buf.read_ub4()? as usize;
        let bit_vector = if num_bytes == 0 {
            None
        } else {
            let expected_bytes = column_count.div_ceil(8);
            if num_bytes != expected_bytes {
                return Err(Error::Protocol(
                    "Oracle row bit vector width does not match its metadata".to_string(),
                ));
            }
            buf.skip_ub1()?; // repeated length
            Some(buf.read_bytes_vec(num_bytes)?)
        };
        let rxhrid_len = buf.read_ub4()? as usize;
        self.skip_bounded_bytes_with_outer_length(buf, rxhrid_len)?;
        Ok(bit_vector)
    }

    /// Parse return parameters (TNS_MSG_TYPE_PARAMETER = 8)
    fn parse_return_parameters(&self, buf: &mut ReadBuffer) -> Result<()> {
        self.parse_return_parameters_internal(buf, false)
            .map(|_| ())
    }

    /// Skip a TTC byte sequence preceded by an outer length field.
    fn skip_bounded_bytes_with_outer_length(
        &self,
        buf: &mut ReadBuffer,
        outer_len: usize,
    ) -> Result<()> {
        let maximum = self.config.wire_limits.max_value_bytes;
        if outer_len > maximum {
            return Err(Error::LimitExceeded);
        }
        if outer_len > 0 {
            buf.skip_bytes_with_length_bounded(maximum)?;
        }
        Ok(())
    }

    /// Parse return parameters with optional row counts extraction
    /// When `want_row_counts` is true, attempts to read arraydmlrowcounts from the response.
    fn parse_return_parameters_internal(
        &self,
        buf: &mut ReadBuffer,
        want_row_counts: bool,
    ) -> Result<Option<Vec<u64>>> {
        // Per Python's _process_return_parameters
        let num_params = buf.read_ub2()?; // al8o4l (ignored)
        for _ in 0..num_params {
            buf.skip_ub4()?;
        }

        let al8txl = buf.read_ub2()?; // al8txl (ignored)
        if al8txl > 0 {
            buf.skip(al8txl as usize)?;
        }

        // num key/value pairs - skip for now
        let num_pairs = buf.read_ub2()?;
        for _ in 0..num_pairs {
            let text_len = buf.read_ub2()? as usize;
            self.skip_bounded_bytes_with_outer_length(buf, text_len)?;
            let binary_len = buf.read_ub2()? as usize;
            self.skip_bounded_bytes_with_outer_length(buf, binary_len)?;
            buf.skip_ub2()?; // keyword num
        }

        // registration
        let num_bytes = buf.read_ub2()?;
        if num_bytes > 0 {
            buf.skip(num_bytes as usize)?;
        }

        // If arraydmlrowcounts was requested, parse the row counts
        if want_row_counts && buf.remaining() >= 4 {
            let num_rows = buf.read_ub4()? as usize;
            let mut row_counts = Vec::with_capacity(num_rows);
            for _ in 0..num_rows {
                let count = buf.read_ub8()?;
                row_counts.push(count);
            }
            Ok(Some(row_counts))
        } else {
            Ok(None)
        }
    }

    /// Parse a single row of data
    fn parse_row_data_single(
        &self,
        buf: &mut ReadBuffer,
        columns: &[ColumnInfo],
        caps: &Capabilities,
    ) -> Result<Row> {
        let mut values = Vec::with_capacity(columns.len());

        for col in columns {
            let value = self.parse_column_value(buf, col, caps)?;
            values.push(value);
        }

        Ok(Row::new(values))
    }

    /// Parse a single row of data with bit vector support for duplicate column optimization
    ///
    /// Oracle sends a BitVector message before RowData when some columns have the same
    /// value as the previous row. Bits that are SET (1) indicate data is sent in the buffer;
    /// bits that are CLEAR (0) indicate the value should be copied from the previous row.
    fn parse_row_data_with_bitvector(
        &self,
        buf: &mut ReadBuffer,
        columns: &[ColumnInfo],
        caps: &Capabilities,
        bit_vector: Option<&[u8]>,
        previous_values: Option<&Vec<Value>>,
    ) -> Result<Row> {
        let mut values = Vec::with_capacity(columns.len());

        for (col_idx, col) in columns.iter().enumerate() {
            // Check if this column is a duplicate (bit=0 means duplicate)
            let is_duplicate = if let Some(bv) = bit_vector {
                let byte_num = col_idx / 8;
                let bit_num = col_idx % 8;
                if byte_num < bv.len() {
                    // If bit is 0, it's a duplicate
                    (bv[byte_num] & (1 << bit_num)) == 0
                } else {
                    false
                }
            } else {
                false
            };

            if is_duplicate {
                let previous = previous_values.ok_or_else(|| {
                    Error::Protocol("Oracle duplicate row value has no preceding row".to_string())
                })?;
                let value = previous.get(col_idx).ok_or_else(|| {
                    Error::Protocol(
                        "Oracle duplicate row value exceeds the preceding row width".to_string(),
                    )
                })?;
                values.push(value.clone());
            } else {
                // Read actual value from buffer
                let value = self.parse_column_value(buf, col, caps)?;
                values.push(value);
            }
        }

        Ok(Row::new(values))
    }

    /// Parse a single column value from the buffer
    fn parse_column_value(
        &self,
        buf: &mut ReadBuffer,
        col: &ColumnInfo,
        caps: &Capabilities,
    ) -> Result<Value> {
        use crate::constants::OracleType;

        if self.config.value_decode_policy == ValueDecodePolicy::CoreScalar
            && (col.is_json
                || col.is_oson
                || col.vector_dimensions.is_some()
                || col.vector_format.is_some()
                || !matches!(
                    col.oracle_type,
                    OracleType::Number
                        | OracleType::Date
                        | OracleType::Timestamp
                        | OracleType::Varchar
                        | OracleType::Char
                        | OracleType::Raw
                ))
        {
            return Err(Error::DataConversionError(
                "Oracle wire type is disabled by the value decoding policy".to_string(),
            ));
        }

        // Handle LOB columns specially - they have a different format
        if col.is_lob() {
            return self.parse_lob_value(buf, col);
        }

        // Handle CURSOR type - REF CURSOR from PL/SQL
        if col.oracle_type == OracleType::Cursor {
            return self.parse_cursor_value(buf, caps);
        }

        // Handle Object type - collections (VARRAY, Nested Table) and UDTs
        if col.oracle_type == OracleType::Object {
            return self.parse_object_value(buf, col);
        }

        // Read the value based on the column type
        // First, check if it's NULL
        let data = buf.read_bytes_with_length_bounded(self.config.wire_limits.max_value_bytes)?;

        match data {
            None => Ok(Value::Null),
            Some(bytes) if bytes.is_empty() => Ok(Value::Null),
            Some(bytes) => {
                // Decode based on oracle type
                match col.oracle_type {
                    OracleType::Number => {
                        // Oracle NUMBER format - decode to string
                        let num = crate::types::decode_oracle_number(&bytes)?;
                        Ok(Value::String(num.value))
                    }
                    OracleType::Varchar | OracleType::Char | OracleType::Long => {
                        let s = if col.csfrm == 2 {
                            decode_utf16_be(&bytes)?
                        } else {
                            String::from_utf8(bytes).map_err(|_| {
                                Error::DataConversionError(
                                    "Oracle text is not valid UTF-8".to_string(),
                                )
                            })?
                        };
                        Ok(Value::String(s))
                    }
                    OracleType::Raw | OracleType::LongRaw => {
                        // RAW/LONG RAW types - return as bytes
                        Ok(Value::Bytes(bytes))
                    }
                    OracleType::Date => {
                        // Oracle DATE format - 7 bytes
                        let date = crate::types::decode_oracle_date(&bytes)?;
                        Ok(Value::Date(date))
                    }
                    OracleType::Timestamp | OracleType::TimestampLtz => {
                        // Oracle TIMESTAMP format - 11 bytes (date + fractional seconds)
                        let ts = crate::types::decode_oracle_timestamp(&bytes)?;
                        Ok(Value::Timestamp(ts))
                    }
                    OracleType::TimestampTz => {
                        // Oracle TIMESTAMP WITH TIME ZONE - 13 bytes
                        let ts = crate::types::decode_oracle_timestamp(&bytes)?;
                        Ok(Value::Timestamp(ts))
                    }
                    unsupported => Err(Error::DataConversionError(format!(
                        "unsupported Oracle wire type {unsupported:?}"
                    ))),
                }
            }
        }
    }

    /// Parse a REF CURSOR value from the buffer
    ///
    /// Per Python base.pyx lines 1038-1046:
    /// - Skip 1 byte (length indicator - fixed value)
    /// - Read describe info (column metadata for the cursor)
    /// - Read cursor_id (UB2)
    fn parse_cursor_value(&self, buf: &mut ReadBuffer, caps: &Capabilities) -> Result<Value> {
        use crate::types::RefCursor;

        // Skip length indicator (fixed value for cursors)
        let _length = buf.read_u8()?;

        // Read column metadata for this cursor
        let cursor_columns = self.parse_describe_info(buf, caps.ttc_field_version)?;

        // Read the cursor ID
        let cursor_id = buf.read_ub2()?;

        // Create RefCursor with the metadata
        let ref_cursor = RefCursor::new(cursor_id, cursor_columns);

        Ok(Value::Cursor(ref_cursor))
    }

    /// Parse an Object/Collection value from the buffer
    ///
    /// Object format from Oracle (per Python packet.pyx read_dbobject):
    /// - UB4: type OID length, then TTC length-prefixed type OID if > 0
    /// - UB4: OID length, then TTC length-prefixed OID if > 0
    /// - UB4: snapshot length, then TTC length-prefixed snapshot if > 0
    /// - UB2: version (skip)
    /// - UB4: packed data length
    /// - UB2: flags (skip)
    /// - Bytes: packed data (pickle format)
    fn parse_object_value(&self, buf: &mut ReadBuffer, col: &ColumnInfo) -> Result<Value> {
        use crate::dbobject::{CollectionType, DbObject, DbObjectType};
        use crate::types::decode_collection;

        // Read and discard type OID
        let toid_len = buf.read_ub4()? as usize;
        self.skip_bounded_bytes_with_outer_length(buf, toid_len)?;

        // Read and discard OID
        let oid_len = buf.read_ub4()? as usize;
        self.skip_bounded_bytes_with_outer_length(buf, oid_len)?;

        // Read and discard snapshot
        let snapshot_len = buf.read_ub4()? as usize;
        self.skip_bounded_bytes_with_outer_length(buf, snapshot_len)?;

        // Skip version (length-prefixed UB2)
        let _version = buf.read_ub2()?;

        // Read packed data length
        let data_len = buf.read_ub4()? as usize;
        if data_len > self.config.wire_limits.max_value_bytes {
            return Err(Error::LimitExceeded);
        }

        // Skip flags (length-prefixed UB2)
        let _flags = buf.read_ub2()?;

        if data_len == 0 {
            return Ok(Value::Null);
        }

        // Read packed data (chunked format like other byte sequences)
        let packed_data =
            buf.read_bytes_with_length_bounded(self.config.wire_limits.max_value_bytes)?;

        match packed_data {
            None => Ok(Value::Null),
            Some(data) if data.is_empty() => Ok(Value::Null),
            Some(data) => {
                // Create a placeholder type based on column info
                let type_name = col
                    .type_name
                    .clone()
                    .unwrap_or_else(|| "UNKNOWN".to_string());

                // Try to determine if this is a collection based on the pickle data
                // The first byte contains flags - check for IS_COLLECTION (0x08)
                let is_collection = !data.is_empty() && (data[0] & 0x08) != 0;

                if is_collection {
                    // Get element type from column info or default to VARCHAR
                    let element_type = col
                        .element_type
                        .unwrap_or(crate::constants::OracleType::Varchar);

                    // Determine collection type from pickle flags
                    // Collection flags are after header - but we'll default for now
                    let collection_type = CollectionType::Varray;

                    let obj_type = DbObjectType::collection(
                        &col.type_schema.clone().unwrap_or_default(),
                        &type_name,
                        collection_type,
                        element_type,
                    );

                    match decode_collection(&obj_type, &data) {
                        Ok(collection) => Ok(Value::Collection(collection)),
                        Err(e) => {
                            let _ = e;
                            // Return raw bytes as fallback
                            Ok(Value::Bytes(data))
                        }
                    }
                } else {
                    // Regular object type - not yet fully implemented
                    let mut obj = DbObject::new(&type_name);
                    // Store raw pickle data for later inspection
                    obj.set("_raw_data", Value::Bytes(data));
                    Ok(Value::Collection(obj))
                }
            }
        }
    }

    /// Parse a LOB column value from the buffer
    ///
    /// LOB format from Oracle (per Python's read_lob_with_length):
    /// - UB4: num_bytes (indicator that LOB data follows)
    /// - If num_bytes > 0:
    ///   - For non-BFILE: UB8 size, UB4 chunk_size
    ///   - Bytes: LOB locator (chunked format)
    ///
    /// The actual LOB content must be fetched separately using LOB operations.
    /// For JSON columns, the data is OSON-encoded and decoded directly.
    /// For VECTOR columns, the data is decoded from Oracle's vector binary format.
    fn parse_lob_value(&self, buf: &mut ReadBuffer, col: &ColumnInfo) -> Result<Value> {
        use crate::constants::OracleType;
        use crate::types::{decode_vector, OsonDecoder};

        // Read length indicator
        let num_bytes = buf.read_ub4()?;

        if num_bytes == 0 {
            // For JSON, null is Value::Json(serde_json::Value::Null)
            if col.oracle_type == OracleType::Json || col.is_json {
                return Ok(Value::Json(serde_json::Value::Null));
            }
            // For VECTOR, null is Value::Null
            if col.oracle_type == OracleType::Vector {
                return Ok(Value::Null);
            }
            return Ok(Value::Lob(LobValue::Null));
        }

        // For BFILE, there's no size/chunk_size metadata
        let (size, chunk_size) = if col.oracle_type == OracleType::Bfile {
            (0u64, 0u32)
        } else {
            // Read LOB size and chunk size
            let size = buf.read_ub8()?;
            let chunk_size = buf.read_ub4()?;
            (size, chunk_size)
        };

        // Read LOB data (could be locator or inline data depending on size)
        let data_bytes =
            buf.read_bytes_with_length_bounded(self.config.wire_limits.max_value_bytes)?;

        // Handle JSON columns - decode OSON format
        // JSON is sent as a LOB with prefetched data + a LOB locator that must be consumed
        if col.oracle_type == OracleType::Json || col.is_json {
            // Read and discard the LOB locator
            buf.skip_bytes_with_length_bounded(self.config.wire_limits.max_value_bytes)?;

            if let Some(data) = data_bytes {
                if !data.is_empty() {
                    // Decode OSON to JSON
                    match OsonDecoder::decode(bytes::Bytes::from(data)) {
                        Ok(json_value) => return Ok(Value::Json(json_value)),
                        Err(e) => {
                            let _ = e;
                            return Ok(Value::Json(serde_json::Value::Null));
                        }
                    }
                }
            }
            return Ok(Value::Json(serde_json::Value::Null));
        }

        // Handle VECTOR columns - decode vector binary format
        if col.oracle_type == OracleType::Vector {
            // Read and discard LOB locator (not needed for VECTOR)
            buf.skip_bytes_with_length_bounded(self.config.wire_limits.max_value_bytes)?;

            if let Some(data) = data_bytes {
                if !data.is_empty() {
                    match decode_vector(&data) {
                        Ok(vector) => return Ok(Value::Vector(vector)),
                        Err(e) => {
                            let _ = e;
                            return Ok(Value::Null);
                        }
                    }
                }
            }
            return Ok(Value::Null);
        }

        // Create a LOB locator for fetching the data later
        if let Some(locator_data) = data_bytes {
            if !locator_data.is_empty() {
                let locator = LobLocator::new(
                    bytes::Bytes::from(locator_data),
                    size,
                    chunk_size,
                    col.oracle_type,
                    col.csfrm,
                );
                return Ok(Value::Lob(LobValue::locator(locator)));
            }
        }

        // If we have size but no locator, it might be an empty LOB
        if size == 0 {
            return Ok(Value::Lob(LobValue::Empty));
        }

        // Empty LOB (shouldn't normally reach here)
        Ok(Value::Lob(LobValue::Empty))
    }

    /// Parse error info message and extract cursor_id
    /// Format per Python's _process_error_info in base.pyx
    fn parse_error_info(&self, buf: &mut ReadBuffer) -> Result<(u32, Option<String>, u16)> {
        // End of call status
        let _call_status = buf.read_ub4()?;
        // End to end seq#
        buf.skip_ub2()?;
        // Current row number
        buf.skip_ub4()?;
        // Error number (short form)
        buf.skip_ub2()?;
        // Array elem error
        buf.skip_ub2()?;
        // Array elem error
        buf.skip_ub2()?;
        // Cursor ID
        let cursor_id = buf.read_ub2()?;
        // Error position
        let _error_pos = buf.read_sb2()?;
        // SQL type (19c and earlier)
        buf.skip_ub1()?;
        // Fatal?
        buf.skip_ub1()?;
        // Flags
        buf.skip_ub1()?;
        // User cursor options
        buf.skip_ub1()?;
        // UPI parameter
        buf.skip_ub1()?;
        // Flags (second)
        buf.skip_ub1()?;
        // Rowid (rba, partition_id, skip 1, block_num, slot_num)
        buf.skip_ub4()?; // rba
        buf.skip_ub2()?; // partition_id
        buf.skip_ub1()?; // skip
        buf.skip_ub4()?; // block_num
        buf.skip_ub2()?; // slot_num
                         // OS error
        buf.skip_ub4()?;
        // Statement number
        buf.skip_ub1()?;
        // Call number
        buf.skip_ub1()?;
        // Padding
        buf.skip_ub2()?;
        // Success iters
        buf.skip_ub4()?;
        // oerrdd (logical rowid)
        let oerrdd_len = buf.read_ub4()?;
        if oerrdd_len > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // Batch error codes array
        let num_batch_errors = buf.read_ub2()?;
        if num_batch_errors > 0 {
            buf.skip_ub1()?; // first byte
            for _ in 0..num_batch_errors {
                buf.skip_ub2()?; // error code
            }
        }

        // Batch error row offset array
        let num_offsets = buf.read_ub4()?;
        if num_offsets > 0 {
            buf.skip_ub1()?; // first byte
            for _ in 0..num_offsets {
                buf.skip_ub4()?; // offset
            }
        }

        // Batch error messages array
        let num_batch_msgs = buf.read_ub2()?;
        if num_batch_msgs > 0 {
            buf.skip_ub1()?; // packed size
            for _ in 0..num_batch_msgs {
                buf.skip_ub2()?; // chunk length
                buf.read_string_with_length()?; // message
                buf.skip(2)?; // end marker
            }
        }

        // Extended error number (UB4)
        let error_code = buf.read_ub4()?;
        // Row count (UB8)
        let _row_count = buf.read_ub8()?;

        // Error message
        let error_msg = if error_code != 0 {
            buf.read_string_with_length()?.map(|s| s.trim().to_string())
        } else {
            None
        };

        Ok((error_code, error_msg, cursor_id))
    }

    /// Parse error response packet (received after marker reset)
    fn parse_error_response(&self, payload: &[u8], ttc_field_version: u8) -> Result<QueryResult> {
        if payload.len() < 3 {
            return Err(Error::Protocol("Error response too short".to_string()));
        }

        let mut buf = ReadBuffer::from_slice(payload);

        // Skip data flags
        buf.skip(2)?;

        let msg_type = loop {
            let msg_type = buf.read_u8()?;
            if msg_type != MessageType::Token as u8 {
                break msg_type;
            }
            validate_response_token(&mut buf, NON_PIPELINED_TOKEN_NUMBER)?;
        };

        // Check for error message type (4)
        if msg_type == MessageType::Error as u8 {
            let (error_num, error_msg, _, _) =
                self.parse_error_info_with_rowcount_for_version(&mut buf, ttc_field_version)?;

            return Err(Error::OracleError {
                code: error_num,
                message: error_msg.unwrap_or_else(|| format!("ORA-{:05}", error_num)),
            });
        }

        // If not an error message type, return generic error
        Err(Error::Protocol(format!(
            "Expected error message type 4, got {}",
            msg_type
        )))
    }

    /// Parse DML response to extract rows affected
    fn parse_dml_response(&self, payload: &[u8], ttc_field_version: u8) -> Result<QueryResult> {
        if payload.len() < 3 {
            return Err(Error::Protocol("DML response too short".to_string()));
        }

        let mut buf = ReadBuffer::from_slice(payload);

        // Skip data flags
        buf.skip(2)?;

        let mut rows_affected: u64 = 0;
        let mut cursor_id: u16 = 0;
        let mut end_of_response = false;

        // Process messages until end_of_response or out of data
        // Note: If supports_end_of_response is true, we must continue until msg type 29
        while !end_of_response && buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                x if x == MessageType::Token as u8 => {
                    validate_response_token(&mut buf, NON_PIPELINED_TOKEN_NUMBER)?;
                }

                // Error (4) - may contain error or success info
                x if x == MessageType::Error as u8 => {
                    let (error_code, error_msg, cid, row_count) = self
                        .parse_error_info_with_rowcount_for_version(&mut buf, ttc_field_version)?;
                    cursor_id = cid;
                    rows_affected = row_count;
                    if error_code != 0 && error_code != 1403 {
                        return Err(Error::OracleError {
                            code: error_code,
                            message: error_msg.unwrap_or_default(),
                        });
                    }
                    // Only end if server doesn't support end_of_response
                    // Otherwise, continue until we get msg type 29
                }

                // Parameter (8) - return parameters
                x if x == MessageType::Parameter as u8 => {
                    self.parse_return_parameters(&mut buf)?;
                }

                // Status (9) - call status
                x if x == MessageType::Status as u8 => {
                    let _call_status = buf.read_ub4()?;
                    let _end_to_end_seq = buf.read_ub2()?;
                }

                // BitVector (21)
                21 => {
                    let _num_columns_sent = buf.read_ub2()?;
                    // No columns for DML, but read the byte if present
                    if buf.remaining() > 0 {
                        let _byte = buf.read_u8()?;
                    }
                }

                // End of Response (29) - explicit end marker
                29 => {
                    end_of_response = true;
                }

                _ => {
                    // Unknown message type - continue processing
                }
            }
        }

        Ok(QueryResult {
            columns: Vec::new(),
            rows: Vec::new(),
            rows_affected,
            has_more_rows: false,
            cursor_id,
            response_packet_count: 0,
        })
    }

    fn parse_error_info_with_rowcount_for_version(
        &self,
        buf: &mut ReadBuffer,
        ttc_field_version: u8,
    ) -> Result<(u32, Option<String>, u16, u64)> {
        parse_error_info_with_rowcount_for_version(buf, ttc_field_version)
    }

    /// Parse describe info from response to extract column metadata
    ///
    /// Per Python's _process_describe_info, the format is:
    /// - UB4: max row size (skip)
    /// - UB4: number of columns
    /// - If num_columns > 0: UB1 (skip one byte)
    /// - For each column: metadata fields
    /// - After columns: current date, dcb flags, etc.
    fn parse_describe_info(
        &self,
        buf: &mut ReadBuffer,
        ttc_field_version: u8,
    ) -> Result<Vec<ColumnInfo>> {
        use crate::constants::{ccap_value, uds_flags};

        // Skip max row size
        buf.skip_ub4()?;

        // Read number of columns
        let num_columns = buf.read_ub4()? as usize;
        if num_columns > self.config.wire_limits.max_columns {
            return Err(Error::LimitExceeded);
        }
        if num_columns == 0 {
            return Ok(Vec::new());
        }

        // Skip one byte if we have columns
        buf.skip_ub1()?;

        let mut columns = Vec::with_capacity(num_columns);

        for _col_idx in 0..num_columns {
            // Parse column metadata per Python's _process_metadata
            let ora_type_num = buf.read_u8()?;
            buf.skip_ub1()?; // flags
            let precision = i16::from(buf.read_u8()? as i8);
            let scale = i16::from(buf.read_u8()? as i8);
            let buffer_size = buf.read_ub4()?;

            buf.skip_ub4()?; // max_num_array_elements
            buf.skip_ub8()?; // cont_flags
            let oid_len = buf.read_ub4()? as usize;
            self.skip_bounded_bytes_with_outer_length(buf, oid_len)?; // OID
            buf.skip_ub2()?; // version
            buf.skip_ub2()?; // charset_id
            let csfrm = buf.read_u8()?; // charset form
            let max_size = buf.read_ub4()?;

            // For TTC field version >= 12.2 (8), skip oaccolid
            if ttc_field_version >= ccap_value::FIELD_VERSION_12_2 {
                buf.skip_ub4()?; // oaccolid
            }

            let nulls_allowed = buf.read_u8()?;
            buf.skip_ub1()?; // v7 length of name
            let name = buf.read_string_with_ub4_length()?.unwrap_or_default();
            let type_schema = buf.read_string_with_ub4_length()?; // schema
            let type_name = buf.read_string_with_ub4_length()?; // type_name
            buf.skip_ub2()?; // column position
            let uds_metadata_flags = buf.read_ub4()?;

            // For TTC field version >= 23.1 (17), read domain fields
            let mut domain_schema = None;
            let mut domain_name = None;
            if ttc_field_version >= ccap_value::FIELD_VERSION_23_1 {
                domain_schema = buf.read_string_with_ub4_length()?;
                domain_name = buf.read_string_with_ub4_length()?;
            }

            // For TTC field version >= 20 (23.1_EXT_3), read annotations
            if ttc_field_version >= 20 {
                let num_annotations = buf.read_ub4()?;
                if num_annotations > 0 {
                    buf.skip_ub1()?;
                    // Read the actual annotations count (yes, it's read twice in Python)
                    let actual_num = buf.read_ub4()?;
                    buf.skip_ub1()?;
                    for _ in 0..actual_num {
                        // Skip annotation key and value (both are string with UB4 length)
                        let _key = buf.read_string_with_ub4_length()?;
                        let _value = buf.read_string_with_ub4_length()?;
                        buf.skip_ub4()?; // flags per annotation
                    }
                    buf.skip_ub4()?; // final flags
                }
            }

            // For TTC field version >= 24 (23.4), read vector fields
            let mut vector_dimensions = None;
            let mut vector_format = None;
            if ttc_field_version >= ccap_value::FIELD_VERSION_23_4 {
                let dimensions = buf.read_ub4()?;
                vector_format = Some(buf.read_u8()?);
                let vector_flags = buf.read_u8()?;
                if (vector_flags & 0x01) == 0 {
                    vector_dimensions = Some(dimensions);
                }
            }

            // Convert data type to OracleType
            let oracle_type = oracle_type_from_wire_code(ora_type_num)?;

            let mut col = ColumnInfo::new(&name, oracle_type);
            col.data_size = if max_size > 0 { max_size } else { buffer_size };
            col.buffer_size = buffer_size;
            col.precision = precision;
            col.scale = scale;
            col.nullable = nulls_allowed != 0;
            col.csfrm = csfrm;
            col.type_schema = type_schema;
            col.type_name = type_name;
            col.domain_schema = domain_schema;
            col.domain_name = domain_name;
            col.is_json =
                oracle_type == OracleType::Json || (uds_metadata_flags & uds_flags::IS_JSON) != 0;
            col.is_oson = (uds_metadata_flags & uds_flags::IS_OSON) != 0;
            col.vector_dimensions = vector_dimensions;
            col.vector_format = vector_format;
            columns.push(col);
        }

        // After columns: skip remaining describe info fields
        // Python's _process_describe_info uses:
        //   buf.read_ub4(&num_bytes)
        //   if num_bytes > 0:
        //       buf.skip_raw_bytes_chunked()    # current date
        //   buf.skip_ub4()                      # dcbflag
        //   buf.skip_ub4()                      # dcbmdbz
        //   buf.skip_ub4()                      # dcbmnpr
        //   buf.skip_ub4()                      # dcbmxpr
        //   buf.read_ub4(&num_bytes)
        //   if num_bytes > 0:
        //       buf.skip_raw_bytes_chunked()    # dcbqcky

        // current_date - read UB4 indicator first, then skip chunked bytes if > 0
        let current_date_indicator = buf.read_ub4()?;
        if current_date_indicator > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // dcb* fields as UB4
        buf.skip_ub4()?; // dcbflag
        buf.skip_ub4()?; // dcbmdbz
        buf.skip_ub4()?; // dcbmnpr
        buf.skip_ub4()?; // dcbmxpr

        // dcbqcky - read UB4 indicator first, then skip chunked bytes if > 0
        let dcbqcky_indicator = buf.read_ub4()?;
        if dcbqcky_indicator > 0 {
            buf.skip_raw_bytes_chunked()?;
        }

        // After dcbqcky, the next message (RowHeader) follows directly
        // No additional fields to skip here

        Ok(columns)
    }

    /// Commit the current transaction.
    ///
    /// Makes all changes in the current transaction permanent. After commit,
    /// a new transaction begins automatically.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use oracle_rs::{Connection, Value};
    /// # async fn example(conn: Connection) -> oracle_rs::Result<()> {
    /// conn.execute("INSERT INTO users (name) VALUES (:1)", &["Alice".into()]).await?;
    /// conn.execute("INSERT INTO users (name) VALUES (:1)", &["Bob".into()]).await?;
    /// conn.commit().await?; // Both inserts are now permanent
    /// # Ok(())
    /// # }
    /// ```
    pub async fn commit(&self) -> Result<()> {
        self.ensure_ready().await?;
        // Use SQL COMMIT statement instead of simple function
        // The simple function protocol triggers BREAK marker + connection close on Oracle Free 23ai
        self.execute("COMMIT", &[]).await?;
        Ok(())
    }

    /// Rollback the current transaction.
    ///
    /// Discards all changes made in the current transaction. After rollback,
    /// a new transaction begins automatically.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use oracle_rs::{Connection, Value};
    /// # async fn example(conn: Connection) -> oracle_rs::Result<()> {
    /// conn.execute("DELETE FROM users WHERE id = :1", &[1.into()]).await?;
    /// // Oops, wrong user!
    /// conn.rollback().await?; // Delete is undone
    /// # Ok(())
    /// # }
    /// ```
    pub async fn rollback(&self) -> Result<()> {
        self.ensure_ready().await?;
        // Use SQL ROLLBACK statement instead of simple function
        // The simple function protocol triggers BREAK marker + connection close on Oracle Free 23ai
        self.execute("ROLLBACK", &[]).await?;
        Ok(())
    }

    /// Create a savepoint within the current transaction
    ///
    /// Savepoints allow partial rollback of a transaction. You can create multiple
    /// savepoints and rollback to any of them without affecting work done before
    /// that savepoint.
    ///
    /// # Arguments
    /// * `name` - The savepoint name (must be a valid Oracle identifier)
    ///
    /// # Example
    /// ```rust,ignore
    /// conn.execute("INSERT INTO t VALUES (1)", &[]).await?;
    /// conn.savepoint("sp1").await?;
    /// conn.execute("INSERT INTO t VALUES (2)", &[]).await?;
    /// conn.rollback_to_savepoint("sp1").await?; // Undoes the second insert
    /// conn.commit().await?; // Commits only the first insert
    /// ```
    pub async fn savepoint(&self, name: &str) -> Result<()> {
        self.ensure_ready().await?;
        self.execute(&format!("SAVEPOINT {}", name), &[]).await?;
        Ok(())
    }

    /// Rollback to a previously created savepoint
    ///
    /// This undoes all changes made after the savepoint was created, but keeps
    /// the transaction active. Changes made before the savepoint are preserved.
    ///
    /// # Arguments
    /// * `name` - The savepoint name to rollback to
    pub async fn rollback_to_savepoint(&self, name: &str) -> Result<()> {
        self.ensure_ready().await?;
        self.execute(&format!("ROLLBACK TO SAVEPOINT {}", name), &[])
            .await?;
        Ok(())
    }

    /// Ping the server to check if the connection is still alive.
    ///
    /// This executes a lightweight query (`SELECT 1 FROM DUAL`) to verify
    /// the connection is responsive. Useful for connection health checks
    /// in pooling scenarios.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use oracle_rs::Connection;
    /// # async fn example(conn: Connection) -> oracle_rs::Result<()> {
    /// if conn.ping().await.is_ok() {
    ///     println!("Connection is alive");
    /// } else {
    ///     println!("Connection is dead");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub async fn ping(&self) -> Result<()> {
        self.ensure_ready().await?;
        // Use SELECT FROM DUAL instead of simple function
        // The simple function protocol triggers BREAK marker + connection close on Oracle Free 23ai
        self.query("SELECT 1 FROM DUAL", &[]).await?;
        Ok(())
    }

    /// Clear the statement cache
    ///
    /// This should be called when recycling a connection in a pool to ensure
    /// that any stale cursor state is cleared. This is useful after errors
    /// or when the connection state may be inconsistent.
    pub async fn clear_statement_cache(&self) {
        let mut inner = self.inner.lock().await;
        if let Some(ref mut cache) = inner.statement_cache {
            cache.clear();
        }
    }

    /// Read data from a LOB (CLOB or BLOB)
    ///
    /// # Arguments
    /// * `locator` - The LOB locator obtained from a query result
    /// * `offset` - Starting position (1-based, in characters for CLOB, bytes for BLOB)
    /// * `amount` - Amount to read (0 for entire LOB)
    ///
    /// # Returns
    /// For CLOB: returns the text content as a String
    /// For BLOB: returns the binary content as bytes
    pub async fn read_lob(&self, locator: &LobLocator) -> Result<LobData> {
        self.ensure_ready().await?;

        // Read the entire LOB starting at offset 1
        let offset = 1u64;
        let amount = locator.size();

        self.read_lob_internal(locator, offset, amount).await
    }

    /// Read a portion of a LOB
    pub async fn read_lob_range(
        &self,
        locator: &LobLocator,
        offset: u64,
        amount: u64,
    ) -> Result<LobData> {
        self.ensure_ready().await?;
        self.read_lob_internal(locator, offset, amount).await
    }

    /// Read a CLOB and return as String
    ///
    /// This is a convenience method for reading CLOB data directly as a String.
    /// Returns an error if the LOB is not a CLOB.
    pub async fn read_clob(&self, locator: &LobLocator) -> Result<String> {
        if locator.is_blob() || locator.is_bfile() {
            return Err(Error::Protocol(
                "Cannot read BLOB/BFILE as string, use read_blob instead".to_string(),
            ));
        }

        let data = self.read_lob(locator).await?;
        match data {
            LobData::String(s) => Ok(s),
            LobData::Bytes(_) => Err(Error::Protocol(
                "Unexpected bytes from CLOB read".to_string(),
            )),
        }
    }

    /// Read a BLOB and return as bytes
    ///
    /// This is a convenience method for reading BLOB data directly as bytes.
    /// Returns an error if the LOB is a CLOB (use read_clob instead).
    pub async fn read_blob(&self, locator: &LobLocator) -> Result<bytes::Bytes> {
        if locator.is_clob() {
            return Err(Error::Protocol(
                "Cannot read CLOB as bytes, use read_clob instead".to_string(),
            ));
        }

        let data = self.read_lob(locator).await?;
        match data {
            LobData::Bytes(b) => Ok(b),
            LobData::String(_) => Err(Error::Protocol(
                "Unexpected string from BLOB read".to_string(),
            )),
        }
    }

    /// Read a LOB in chunks, calling a callback for each chunk
    ///
    /// This is useful for processing large LOBs without loading the entire
    /// content into memory. The callback receives each chunk as it's read.
    ///
    /// # Arguments
    /// * `locator` - The LOB locator
    /// * `chunk_size` - Size of each chunk to read (0 uses the LOB's natural chunk size)
    /// * `callback` - Async function called for each chunk
    ///
    /// # Example
    /// ```ignore
    /// let mut total_size = 0;
    /// conn.read_lob_chunked(&locator, 8192, |chunk| async move {
    ///     match chunk {
    ///         LobData::Bytes(b) => total_size += b.len(),
    ///         LobData::String(s) => total_size += s.len(),
    ///     }
    ///     Ok(())
    /// }).await?;
    /// ```
    pub async fn read_lob_chunked<F, Fut>(
        &self,
        locator: &LobLocator,
        chunk_size: u64,
        mut callback: F,
    ) -> Result<()>
    where
        F: FnMut(LobData) -> Fut,
        Fut: std::future::Future<Output = Result<()>>,
    {
        self.ensure_ready().await?;

        let total_size = locator.size();
        if total_size == 0 {
            return Ok(());
        }

        // Use LOB's natural chunk size if not specified
        let chunk_size = if chunk_size == 0 {
            self.lob_chunk_size(locator).await?.max(8192) as u64
        } else {
            chunk_size
        };

        let mut offset = 1u64;
        while offset <= total_size {
            let remaining = total_size - offset + 1;
            let amount = std::cmp::min(remaining, chunk_size);

            let chunk = self.read_lob_internal(locator, offset, amount).await?;
            callback(chunk).await?;

            offset += amount;
        }

        Ok(())
    }

    /// Get the optimal chunk size for a LOB
    ///
    /// This returns the chunk size that Oracle recommends for efficient
    /// reading and writing to this LOB.
    pub async fn lob_chunk_size(&self, locator: &LobLocator) -> Result<u32> {
        self.ensure_ready().await?;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Create LOB operation message for get chunk size
        let mut lob_msg = LobOpMessage::new_get_chunk_size(locator);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        // Build and send the request
        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response
        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty LOB chunk size response".to_string()));
        }

        // Check for MARKER packet
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = crate::buffer::ReadBuffer::from_slice(payload);
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        // Parse the amount response (chunk size is returned as amount)
        self.parse_lob_amount_response(&response[PACKET_HEADER_SIZE..], locator)
            .map(|v| v as u32)
    }

    /// Internal LOB read implementation
    async fn read_lob_internal(
        &self,
        locator: &LobLocator,
        offset: u64,
        amount: u64,
    ) -> Result<LobData> {
        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Create LOB operation message for read
        let mut lob_msg = LobOpMessage::new_read(locator, offset, amount);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        // Build and send the request
        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response (may span multiple packets for large LOBs)
        let response = inner.receive_response().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty LOB read response".to_string()));
        }

        // Check for MARKER packet (indicates error)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = crate::buffer::ReadBuffer::from_slice(payload);
            // Skip data flags
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        // Parse LOB data response
        let payload = &response[PACKET_HEADER_SIZE..];
        self.parse_lob_read_response(payload, locator)
    }

    /// Parse LOB read response
    fn parse_lob_read_response(&self, payload: &[u8], locator: &LobLocator) -> Result<LobData> {
        use crate::buffer::ReadBuffer;

        let mut buf = ReadBuffer::from_slice(payload);

        // Skip data flags
        buf.skip(2)?;

        let mut lob_data: Option<Vec<u8>> = None;

        // Process messages until end of response
        while buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                x if x == MessageType::Token as u8 => {
                    validate_response_token(&mut buf, NON_PIPELINED_TOKEN_NUMBER)?;
                }

                // LobData message (14)
                x if x == MessageType::LobData as u8 => {
                    // Read LOB data with length
                    let data = buf.read_raw_bytes_chunked()?;
                    lob_data = Some(data);
                }

                // Parameter return (8) - contains updated locator and amount
                x if x == MessageType::Parameter as u8 => {
                    // Skip the updated locator (same length as original)
                    let locator_len = locator.locator_bytes().len();
                    buf.skip(locator_len)?;

                    // Read back the amount (ub8)
                    let _returned_amount = buf.read_ub8()?;
                }

                // Error/Status message (4) - code 0 means success
                x if x == MessageType::Error as u8 => {
                    // Parse error info - code 0 means success
                    if let Ok((code, msg, _)) = self.parse_error_info(&mut buf) {
                        if code != 0 {
                            let message = msg.unwrap_or_else(|| "LOB error".to_string());
                            return Err(Error::OracleError { code, message });
                        }
                        // code 0 = success, continue processing
                    }
                }

                // End of response (29)
                x if x == MessageType::EndOfResponse as u8 => {
                    break;
                }

                // Skip other message types
                _ => {
                    // Try to skip unknown messages
                    continue;
                }
            }
        }

        // Convert to appropriate type based on LOB type
        match lob_data {
            Some(data) => {
                if locator.is_blob() || locator.is_bfile() {
                    Ok(LobData::Bytes(bytes::Bytes::from(data)))
                } else {
                    // CLOB - decode based on encoding
                    let text = if locator.uses_var_length_charset() {
                        // UTF-16 BE encoding
                        decode_utf16_be(&data)?
                    } else {
                        // UTF-8 encoding
                        String::from_utf8(data).map_err(|_| {
                            Error::DataConversionError("Oracle CLOB is not valid UTF-8".to_string())
                        })?
                    };
                    Ok(LobData::String(text))
                }
            }
            None => {
                // Empty LOB
                if locator.is_blob() || locator.is_bfile() {
                    Ok(LobData::Bytes(bytes::Bytes::new()))
                } else {
                    Ok(LobData::String(String::new()))
                }
            }
        }
    }

    /// Write data to a LOB
    ///
    /// # Arguments
    /// * `locator` - The LOB locator obtained from a query result
    /// * `offset` - Starting position (1-based, in characters for CLOB, bytes for BLOB)
    /// * `data` - Data to write (bytes for BLOB, UTF-8 encoded bytes for CLOB)
    pub async fn write_lob(&self, locator: &LobLocator, offset: u64, data: &[u8]) -> Result<()> {
        self.ensure_ready().await?;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;
        let sdu_size = inner.sdu_size as usize;

        // Encode data for CLOB if necessary
        let encoded_data: Vec<u8>;
        let write_data = if locator.is_clob() && locator.uses_var_length_charset() {
            // Convert UTF-8 to UTF-16 BE for CLOB with var length charset
            let text = std::str::from_utf8(data).map_err(|_| {
                Error::DataConversionError("Oracle CLOB input is not valid UTF-8".to_string())
            })?;
            encoded_data = text.encode_utf16().flat_map(|c| c.to_be_bytes()).collect();
            &encoded_data[..]
        } else {
            data
        };

        // Create LOB operation message for write
        let mut lob_msg = LobOpMessage::new_write(locator, offset, write_data);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        // Build message content (without packet header or data flags)
        let message = lob_msg.build_message_only(&inner.capabilities)?;

        // Calculate if this fits in a single packet
        // Single packet max payload = SDU - header (8) - data flags (2)
        let max_single_packet_payload = sdu_size.saturating_sub(PACKET_HEADER_SIZE + 2);

        let is_multi_packet = message.len() > max_single_packet_payload;

        if is_multi_packet {
            // Needs multiple packets - use multi-packet sender
            inner.send_multi_packet(&message, 0).await?;
        } else {
            // Fits in one packet - use standard send
            let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
            inner.send(&request).await?;
        }

        // Receive and parse response
        // Use receive_response() to accumulate all packets until END_OF_RESPONSE.
        // This is necessary because Oracle may send multiple packets for the response,
        // and if we only read one packet, leftover data causes close() to hang.
        let response = inner.receive_response().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty LOB write response".to_string()));
        }

        // Check for MARKER packet (indicates error)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = crate::buffer::ReadBuffer::from_slice(payload);
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        // Parse response to check for errors
        self.parse_lob_simple_response(&response[PACKET_HEADER_SIZE..], locator)
    }

    /// Write string data to a CLOB
    pub async fn write_clob(&self, locator: &LobLocator, offset: u64, text: &str) -> Result<()> {
        if locator.is_blob() || locator.is_bfile() {
            return Err(Error::Protocol(
                "Cannot write string to BLOB/BFILE, use write_blob instead".to_string(),
            ));
        }
        self.write_lob(locator, offset, text.as_bytes()).await
    }

    /// Write binary data to a BLOB
    pub async fn write_blob(&self, locator: &LobLocator, offset: u64, data: &[u8]) -> Result<()> {
        if locator.is_clob() {
            return Err(Error::Protocol(
                "Cannot write bytes to CLOB, use write_clob instead".to_string(),
            ));
        }
        self.write_lob(locator, offset, data).await
    }

    /// Get the length of a LOB
    ///
    /// For CLOB: returns length in characters
    /// For BLOB: returns length in bytes
    pub async fn lob_length(&self, locator: &LobLocator) -> Result<u64> {
        self.ensure_ready().await?;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Create LOB operation message for get length
        let mut lob_msg = LobOpMessage::new_get_length(locator);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        // Build and send the request
        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response
        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty LOB get_length response".to_string()));
        }

        // Check for MARKER packet (indicates error)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = crate::buffer::ReadBuffer::from_slice(payload);
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        // Parse response to get the length
        self.parse_lob_amount_response(&response[PACKET_HEADER_SIZE..], locator)
    }

    /// Trim a LOB to a specified length
    ///
    /// # Arguments
    /// * `locator` - The LOB locator
    /// * `new_size` - The new size (in characters for CLOB, bytes for BLOB)
    pub async fn lob_trim(&self, locator: &LobLocator, new_size: u64) -> Result<()> {
        self.ensure_ready().await?;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Create LOB operation message for trim
        let mut lob_msg = LobOpMessage::new_trim(locator, new_size);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        // Build and send the request
        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response
        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty LOB trim response".to_string()));
        }

        // Check for MARKER packet (indicates error)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = crate::buffer::ReadBuffer::from_slice(payload);
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        // Parse response to check for errors
        self.parse_lob_simple_response(&response[PACKET_HEADER_SIZE..], locator)
    }

    /// Create a temporary LOB on the server
    ///
    /// Creates a temporary LOB of the specified type that lives until the connection
    /// is closed or the LOB is explicitly freed.
    ///
    /// # Arguments
    /// * `oracle_type` - The LOB type to create (Clob or Blob)
    ///
    /// # Returns
    /// A `LobLocator` for the newly created temporary LOB
    ///
    /// # Example
    /// ```ignore
    /// use oracle_rs::OracleType;
    ///
    /// let locator = conn.create_temp_lob(OracleType::Clob).await?;
    /// conn.write_clob(&locator, 1, "Hello, World!").await?;
    /// // Now bind the locator to insert into a CLOB column
    /// ```
    pub async fn create_temp_lob(&self, oracle_type: OracleType) -> Result<LobLocator> {
        use crate::buffer::ReadBuffer;

        // Validate oracle_type is a LOB type
        match oracle_type {
            OracleType::Clob | OracleType::Blob => {}
            _ => {
                return Err(Error::Protocol(format!(
                    "create_temp_lob: invalid type {:?}, must be Clob or Blob",
                    oracle_type
                )));
            }
        }

        self.ensure_ready().await?;

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        // Create the CREATE_TEMP message
        let mut lob_msg = LobOpMessage::new_create_temp(oracle_type);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        // Build and send the request
        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        // Receive and parse response
        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol(
                "Empty CREATE_TEMP LOB response".to_string(),
            ));
        }

        // Check for MARKER packet (indicates error)
        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = ReadBuffer::from_slice(payload);
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        // Parse response to extract the locator
        let payload = &response[PACKET_HEADER_SIZE..];
        let mut buf = ReadBuffer::from_slice(payload);
        buf.skip(2)?; // Skip data flags

        let mut locator_bytes: Option<Vec<u8>> = None;

        while buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                x if x == MessageType::Token as u8 => {
                    validate_response_token(&mut buf, NON_PIPELINED_TOKEN_NUMBER)?;
                }

                // Parameter return (8) - contains the populated locator
                x if x == MessageType::Parameter as u8 => {
                    // Read the 40-byte locator (matches the 40 bytes sent in request)
                    let loc_data = buf.read_bytes_vec(40)?;
                    locator_bytes = Some(loc_data);
                    // Skip charset (variable-length ub2) and trailing flags (raw u8)
                    buf.skip_ub2()?;
                    buf.skip(1)?;
                }

                // Error/Status message (4) - code 0 means success
                x if x == MessageType::Error as u8 => {
                    if let Ok((code, msg, _)) = self.parse_error_info(&mut buf) {
                        if code != 0 {
                            let message =
                                msg.unwrap_or_else(|| "CREATE_TEMP LOB error".to_string());
                            return Err(Error::OracleError { code, message });
                        }
                    }
                }

                // End of response (29)
                x if x == MessageType::EndOfResponse as u8 => {
                    break;
                }

                _ => continue,
            }
        }

        // Create the LobLocator from the returned bytes
        let loc_bytes = locator_bytes.ok_or_else(|| {
            Error::Protocol("CREATE_TEMP LOB response did not contain locator".to_string())
        })?;

        // Create LobLocator with size 0, chunk_size 0 (will be fetched if needed)
        let locator = LobLocator::new(
            bytes::Bytes::from(loc_bytes),
            0, // size - unknown for new temp LOB
            0, // chunk_size - unknown, can be fetched later
            oracle_type,
            1, // csfrm - 1 for CLOB, 0 for BLOB (but we store it on the locator type)
        );

        Ok(locator)
    }

    // ==================== BFILE Operations ====================

    /// Check if a BFILE exists on the server
    ///
    /// Returns true if the file referenced by the BFILE locator exists on the server.
    pub async fn bfile_exists(&self, locator: &LobLocator) -> Result<bool> {
        self.ensure_ready().await?;

        if !locator.is_bfile() {
            return Err(Error::Protocol(
                "bfile_exists called on non-BFILE locator".to_string(),
            ));
        }

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        let mut lob_msg = LobOpMessage::new_file_exists(locator);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty BFILE exists response".to_string()));
        }

        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = crate::buffer::ReadBuffer::from_slice(payload);
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        self.parse_lob_bool_response(&response[PACKET_HEADER_SIZE..], locator)
    }

    /// Open a BFILE for reading
    ///
    /// The BFILE must be opened before reading. After reading, close it with bfile_close.
    pub async fn bfile_open(&self, locator: &LobLocator) -> Result<()> {
        self.ensure_ready().await?;

        if !locator.is_bfile() {
            return Err(Error::Protocol(
                "bfile_open called on non-BFILE locator".to_string(),
            ));
        }

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        let mut lob_msg = LobOpMessage::new_file_open(locator);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty BFILE open response".to_string()));
        }

        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = crate::buffer::ReadBuffer::from_slice(payload);
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        self.parse_lob_simple_response(&response[PACKET_HEADER_SIZE..], locator)
    }

    /// Close a BFILE after reading
    pub async fn bfile_close(&self, locator: &LobLocator) -> Result<()> {
        self.ensure_ready().await?;

        if !locator.is_bfile() {
            return Err(Error::Protocol(
                "bfile_close called on non-BFILE locator".to_string(),
            ));
        }

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        let mut lob_msg = LobOpMessage::new_file_close(locator);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty BFILE close response".to_string()));
        }

        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = crate::buffer::ReadBuffer::from_slice(payload);
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        self.parse_lob_simple_response(&response[PACKET_HEADER_SIZE..], locator)
    }

    /// Check if a BFILE is currently open
    pub async fn bfile_is_open(&self, locator: &LobLocator) -> Result<bool> {
        self.ensure_ready().await?;

        if !locator.is_bfile() {
            return Err(Error::Protocol(
                "bfile_is_open called on non-BFILE locator".to_string(),
            ));
        }

        let mut inner = self.inner.lock().await;
        let large_sdu = inner.large_sdu;

        let mut lob_msg = LobOpMessage::new_file_is_open(locator);
        let seq_num = inner.next_sequence_number();
        lob_msg.set_sequence_number(seq_num);

        let request = lob_msg.build_request(&inner.capabilities, large_sdu)?;
        inner.send(&request).await?;

        let response = inner.receive().await?;
        if response.len() <= PACKET_HEADER_SIZE {
            return Err(Error::Protocol("Empty BFILE is_open response".to_string()));
        }

        let packet_type = response[4];
        if packet_type == PacketType::Marker as u8 {
            let error_response = inner.handle_marker_reset().await?;
            let payload = &error_response[PACKET_HEADER_SIZE..];
            let mut buf = crate::buffer::ReadBuffer::from_slice(payload);
            buf.skip(2)?;
            return self.parse_lob_error(&mut buf);
        }

        self.parse_lob_bool_response(&response[PACKET_HEADER_SIZE..], locator)
    }

    /// Read BFILE data
    ///
    /// This is a convenience method that opens the BFILE if needed, reads all content,
    /// and returns it as bytes. For large BFILEs, consider using read_lob_chunked.
    pub async fn read_bfile(&self, locator: &LobLocator) -> Result<bytes::Bytes> {
        if !locator.is_bfile() {
            return Err(Error::Protocol(
                "read_bfile called on non-BFILE locator".to_string(),
            ));
        }

        // Check if file is open, open if needed
        let should_close = if !self.bfile_is_open(locator).await? {
            self.bfile_open(locator).await?;
            true
        } else {
            false
        };

        // Read all data
        let result = self.read_blob(locator).await;

        // Close if we opened it
        if should_close {
            let _ = self.bfile_close(locator).await;
        }

        result
    }

    /// Parse a LOB operation response that returns a boolean (file_exists, is_open)
    fn parse_lob_bool_response(&self, payload: &[u8], locator: &LobLocator) -> Result<bool> {
        use crate::buffer::ReadBuffer;

        let mut buf = ReadBuffer::from_slice(payload);
        buf.skip(2)?; // Skip data flags

        let mut bool_result: bool = false;

        while buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                x if x == MessageType::Token as u8 => {
                    validate_response_token(&mut buf, NON_PIPELINED_TOKEN_NUMBER)?;
                }

                // Parameter return (8) - contains updated locator and bool flag
                x if x == MessageType::Parameter as u8 => {
                    let locator_len = locator.locator_bytes().len();
                    buf.skip(locator_len)?;
                    // Boolean flag is a single byte, > 0 means true
                    let flag = buf.read_u8()?;
                    bool_result = flag > 0;
                }

                // Error/Status message (4) - code 0 means success
                x if x == MessageType::Error as u8 => {
                    if let Ok((code, msg, _)) = self.parse_error_info(&mut buf) {
                        if code != 0 {
                            let message = msg.unwrap_or_else(|| "LOB error".to_string());
                            return Err(Error::OracleError { code, message });
                        }
                    }
                }

                // End of response (29)
                x if x == MessageType::EndOfResponse as u8 => {
                    break;
                }

                _ => continue,
            }
        }

        Ok(bool_result)
    }

    /// Parse a simple LOB operation response (write, trim)
    fn parse_lob_simple_response(&self, payload: &[u8], locator: &LobLocator) -> Result<()> {
        use crate::buffer::ReadBuffer;

        let mut buf = ReadBuffer::from_slice(payload);
        buf.skip(2)?; // Skip data flags

        while buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                x if x == MessageType::Token as u8 => {
                    validate_response_token(&mut buf, NON_PIPELINED_TOKEN_NUMBER)?;
                }

                // Parameter return (8) - contains updated locator and possibly amount
                x if x == MessageType::Parameter as u8 => {
                    let locator_len = locator.locator_bytes().len();
                    buf.skip(locator_len)?;
                    // After locator, there may be amount (ub8) if send_amount was true
                    // We just skip any remaining bytes until we hit Error or EndOfResponse
                }

                // Error/Status message (4) - code 0 means success
                x if x == MessageType::Error as u8 => {
                    if let Ok((code, msg, _)) = self.parse_error_info(&mut buf) {
                        if code != 0 {
                            let message = msg.unwrap_or_else(|| "LOB error".to_string());
                            return Err(Error::OracleError { code, message });
                        }
                    }
                }

                // End of response (29)
                x if x == MessageType::EndOfResponse as u8 => {
                    break;
                }

                _ => continue,
            }
        }

        Ok(())
    }

    /// Parse a LOB operation response that returns an amount (get_length, get_chunk_size)
    fn parse_lob_amount_response(&self, payload: &[u8], locator: &LobLocator) -> Result<u64> {
        use crate::buffer::ReadBuffer;

        let mut buf = ReadBuffer::from_slice(payload);
        buf.skip(2)?; // Skip data flags

        let mut returned_amount: u64 = 0;

        while buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;

            match msg_type {
                x if x == MessageType::Token as u8 => {
                    validate_response_token(&mut buf, NON_PIPELINED_TOKEN_NUMBER)?;
                }

                // Parameter return (8) - contains updated locator and amount
                x if x == MessageType::Parameter as u8 => {
                    let locator_len = locator.locator_bytes().len();
                    buf.skip(locator_len)?;
                    returned_amount = buf.read_ub8()?;
                }

                // Error/Status message (4) - code 0 means success
                x if x == MessageType::Error as u8 => {
                    if let Ok((code, msg, _)) = self.parse_error_info(&mut buf) {
                        if code != 0 {
                            let message = msg.unwrap_or_else(|| "LOB error".to_string());
                            return Err(Error::OracleError { code, message });
                        }
                    }
                }

                // End of response (29)
                x if x == MessageType::EndOfResponse as u8 => {
                    break;
                }

                _ => continue,
            }
        }

        Ok(returned_amount)
    }

    /// Parse LOB error response
    fn parse_lob_error<T>(&self, buf: &mut crate::buffer::ReadBuffer) -> Result<T> {
        // Try to extract error info
        if let Ok((code, msg, _)) = self.parse_error_info(buf) {
            let message = msg.unwrap_or_else(|| "Unknown LOB error".to_string());
            Err(Error::OracleError { code, message })
        } else {
            Err(Error::Protocol("LOB operation failed".to_string()))
        }
    }

    /// Close the connection.
    ///
    /// Sends a logoff message to the server and closes the underlying TCP
    /// connection. After calling close, the connection cannot be reused.
    ///
    /// If the connection is already closed, this method returns `Ok(())`
    /// without doing anything.
    ///
    /// # Note
    ///
    /// Any uncommitted transaction is rolled back by the server when the
    /// connection is closed.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use oracle_rs::{Config, Connection};
    /// # async fn example() -> oracle_rs::Result<()> {
    /// let config = Config::new("localhost", 1521, "FREEPDB1", "user", "password");
    /// let conn = Connection::connect_with_config(config).await?;
    ///
    /// // Do work...
    /// conn.commit().await?;
    ///
    /// // Explicitly close when done
    /// conn.close().await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn close(&self) -> Result<()> {
        if self.closed.swap(true, Ordering::Relaxed) {
            // Already closed
            return Ok(());
        }

        let mut inner = self.inner.lock().await;

        if inner.state == ConnectionState::Ready {
            // Send logoff
            let _ = self
                .send_simple_function_inner(&mut inner, FunctionCode::Logoff)
                .await;
        }

        inner.state = ConnectionState::Closed;

        // Close the TCP stream
        if let Some(stream) = inner.stream.take() {
            drop(stream);
        }

        Ok(())
    }

    /// Send a marker packet to the server
    /// marker_type: 1=BREAK, 2=RESET, 3=INTERRUPT
    async fn send_marker(&self, inner: &mut ConnectionInner, marker_type: u8) -> Result<()> {
        let mut packet_buf = WriteBuffer::new();

        // Build MARKER packet header
        let packet_len = PACKET_HEADER_SIZE + 3; // Header + 3 bytes payload
        packet_buf.write_u16_be(packet_len as u16)?;
        packet_buf.write_u16_be(0)?; // Checksum
        packet_buf.write_u8(PacketType::Marker as u8)?;
        packet_buf.write_u8(0)?; // Flags
        packet_buf.write_u16_be(0)?; // Header checksum

        // Marker payload: [1, 0, marker_type] per Python's _send_marker
        packet_buf.write_u8(1)?;
        packet_buf.write_u8(0)?;
        packet_buf.write_u8(marker_type)?;

        inner.send(&packet_buf.freeze()).await
    }

    async fn send_simple_function_inner(
        &self,
        inner: &mut ConnectionInner,
        function_code: FunctionCode,
    ) -> Result<()> {
        // Build function message
        let mut buf = WriteBuffer::new();

        // Get next sequence number (must be done before sending)
        let seq_num = inner.next_sequence_number();

        // Data flags
        buf.write_u16_be(0)?;
        // Message type: Function
        buf.write_u8(MessageType::Function as u8)?;
        // Function code
        buf.write_u8(function_code as u8)?;
        // Sequence number (tracked per connection)
        buf.write_u8(seq_num)?;

        write_request_token(&mut buf, &inner.capabilities, NON_PIPELINED_TOKEN_NUMBER)?;

        // Build DATA packet
        let data_payload = buf.freeze();
        let mut packet_buf = WriteBuffer::new();
        let packet_len = PACKET_HEADER_SIZE + data_payload.len();
        packet_buf.write_u16_be(packet_len as u16)?;
        packet_buf.write_u16_be(0)?; // Checksum
        packet_buf.write_u8(PacketType::Data as u8)?;
        packet_buf.write_u8(0)?; // Flags
        packet_buf.write_u16_be(0)?; // Header checksum
        packet_buf.write_bytes(&data_payload)?;

        let packet_bytes = packet_buf.freeze();
        inner.send(&packet_bytes).await?;

        // Wait for response
        let response = inner.receive().await?;

        // Check response
        if response.len() <= 4 {
            return Err(Error::Protocol("Response too short".to_string()));
        }

        let packet_type = response[4];

        // MARKER packet (type 12) - need to handle reset protocol
        if packet_type == PacketType::Marker as u8 {
            // Check marker type
            if response.len() >= PACKET_HEADER_SIZE + 3 {
                let marker_type = response[PACKET_HEADER_SIZE + 2];

                // For BREAK marker (1), we need to do the reset protocol
                if marker_type == 1 {
                    // For Logoff, Oracle may send BREAK to indicate "connection closing"
                    // Don't try to do the full reset handshake - just return success
                    if function_code == FunctionCode::Logoff {
                        inner.state = ConnectionState::Closed;
                        return Ok(());
                    }

                    // The BREAK marker means the server is interrupting/breaking the current operation
                    // We MUST complete the reset handshake or the connection will be in a bad state

                    // Send RESET marker to server
                    if let Err(e) = self.send_marker(inner, 2).await {
                        inner.state = ConnectionState::Closed;
                        return Err(e);
                    }

                    // Read and discard packets until we get RESET marker
                    // This follows Python's _reset() logic
                    let mut current_packet_type: u8;
                    loop {
                        match inner.receive().await {
                            Ok(pkt) => {
                                if pkt.len() < PACKET_HEADER_SIZE + 1 {
                                    break;
                                }
                                current_packet_type = pkt[4];

                                if current_packet_type == PacketType::Marker as u8 {
                                    if pkt.len() >= PACKET_HEADER_SIZE + 3 {
                                        let mk_type = pkt[PACKET_HEADER_SIZE + 2];
                                        if mk_type == 2 {
                                            // Got RESET marker, exit this loop
                                            break;
                                        }
                                    }
                                } else {
                                    // Non-marker packet - unexpected during reset wait
                                    break;
                                }
                            }
                            Err(e) => {
                                inner.state = ConnectionState::Closed;
                                return Err(e);
                            }
                        }
                    }

                    // After RESET, continue reading while we still get MARKER packets
                    // Some servers send multiple RESET markers, others send DATA response
                    // Python comment: "some quit immediately" - meaning some servers close
                    // the connection right after the reset handshake
                    loop {
                        match inner.receive().await {
                            Ok(pkt) => {
                                if pkt.len() < PACKET_HEADER_SIZE + 1 {
                                    break;
                                }
                                current_packet_type = pkt[4];

                                if current_packet_type == PacketType::Marker as u8 {
                                    // Another marker, continue reading
                                    continue;
                                }

                                // Got a non-marker packet (probably DATA with error/status)
                                if current_packet_type == PacketType::Data as u8 {
                                    self.parse_simple_function_response(
                                        &pkt[PACKET_HEADER_SIZE..],
                                    )?;
                                }
                                // Exit after processing non-marker packet
                                break;
                            }
                            Err(_) => {
                                // Error reading - connection might be closed
                                // Python comment says "some quit immediately" - meaning some
                                // servers close the connection after BREAK/RESET handshake.
                                // For commit/rollback/logoff, treat this as success since
                                // the operation was processed before the close.
                                if matches!(
                                    function_code,
                                    FunctionCode::Logoff
                                        | FunctionCode::Commit
                                        | FunctionCode::Rollback
                                ) {
                                    // The operation succeeded, but the server closed the connection
                                    // Mark connection as closed for future operations
                                    inner.state = ConnectionState::Closed;
                                    return Ok(());
                                }
                                // For other functions, this means connection is broken
                                inner.state = ConnectionState::Closed;
                                // Don't return error for Ping - treat as success
                                if function_code == FunctionCode::Ping {
                                    return Ok(());
                                }
                                return Ok(()); // Conservative approach - treat as success
                            }
                        }
                    }

                    return Ok(());
                }
            }
            // For non-BREAK markers, just return success
            return Ok(());
        }

        // DATA packet (type 6)
        if packet_type == PacketType::Data as u8 {
            return self.parse_simple_function_response(&response[PACKET_HEADER_SIZE..]);
        }

        Err(Error::Protocol(format!(
            "Unexpected packet type {} for function call",
            packet_type
        )))
    }

    fn parse_simple_function_response(&self, payload: &[u8]) -> Result<()> {
        if payload.len() < 3 {
            return Err(Error::Protocol(
                "Simple function response too short".to_string(),
            ));
        }

        let mut buf = ReadBuffer::from_slice(payload);
        buf.skip(2)?;

        while buf.remaining() > 0 {
            let msg_type = buf.read_u8()?;
            match msg_type {
                x if x == MessageType::Token as u8 => {
                    validate_response_token(&mut buf, NON_PIPELINED_TOKEN_NUMBER)?;
                }
                x if x == MessageType::Error as u8 => {
                    let (error_code, error_msg, _) = self.parse_error_info(&mut buf)?;
                    if error_code != 0 {
                        return Err(Error::OracleError {
                            code: error_code,
                            message: error_msg.unwrap_or_else(|| format!("ORA-{:05}", error_code)),
                        });
                    }
                }
                x if x == MessageType::Parameter as u8 => {
                    self.parse_return_parameters(&mut buf)?;
                }
                x if x == MessageType::Status as u8 => {
                    buf.skip_ub4()?;
                    buf.skip_ub2()?;
                }
                x if x == MessageType::EndOfResponse as u8 => return Ok(()),
                _ => return Err(Error::InvalidMessageType(msg_type)),
            }
        }

        Ok(())
    }

    /// Ensure the connection is ready for operations
    async fn ensure_ready(&self) -> Result<()> {
        if self.is_closed() {
            return Err(Error::ConnectionClosed);
        }

        let inner = self.inner.lock().await;
        if inner.state != ConnectionState::Ready {
            return Err(Error::ConnectionNotReady);
        }

        Ok(())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // Note: Can't do async cleanup in Drop
        // Users should call close() explicitly
        self.closed.store(true, Ordering::Relaxed);
    }
}

// =============================================================================
// Helper functions for get_type()
// =============================================================================

/// Parse a type name into (schema, name) components
///
/// Handles formats like:
/// - "SCHEMA.TYPE_NAME" -> ("SCHEMA", "TYPE_NAME")
/// - "TYPE_NAME" -> (default_schema, "TYPE_NAME")
fn extend_bounded(target: &mut Vec<u8>, bytes: &[u8], maximum: usize) -> Result<()> {
    let required = target
        .len()
        .checked_add(bytes.len())
        .ok_or(Error::LimitExceeded)?;
    if required > maximum {
        return Err(Error::LimitExceeded);
    }
    target
        .try_reserve_exact(bytes.len())
        .map_err(|_| Error::LimitExceeded)?;
    target.extend_from_slice(bytes);
    Ok(())
}

fn increment_response_packet_count(current: usize) -> Result<usize> {
    let next = current.checked_add(1).ok_or(Error::LimitExceeded)?;
    if next > MAX_RESPONSE_PACKETS {
        return Err(Error::LimitExceeded);
    }
    Ok(next)
}

async fn connect_tcp(host: &str, port: u16) -> Result<TcpStream> {
    let addresses = lookup_host((host, port)).await.map_err(|_| Error::Dns)?;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    match last_error {
        Some(error) => Err(Error::Io(error)),
        None => Err(Error::Dns),
    }
}

fn database_version_from_banner(banner: &str) -> Option<String> {
    let mut tokens = banner.split_ascii_whitespace().map(|token| {
        token.trim_matches(|character: char| !character.is_ascii_alphanumeric() && character != '.')
    });

    tokens
        .clone()
        .find(|token| is_dotted_database_version(token))
        .or_else(|| tokens.find(|token| is_marketing_database_version(token)))
        .map(str::to_owned)
}

fn is_dotted_database_version(candidate: &str) -> bool {
    let mut components = candidate.split('.');
    let Some(first) = components.next() else {
        return false;
    };
    if first.is_empty() || !first.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }

    let mut component_count = 1_usize;
    for component in components {
        if component.is_empty() || !component.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        component_count += 1;
    }
    component_count >= 2
}

fn is_marketing_database_version(candidate: &str) -> bool {
    let digit_count = candidate.bytes().take_while(u8::is_ascii_digit).count();
    let suffix = &candidate[digit_count..];
    digit_count > 0
        && (1..=2).contains(&suffix.len())
        && suffix.bytes().all(|byte| byte.is_ascii_alphabetic())
}

fn decode_utf16_be(bytes: &[u8]) -> Result<String> {
    if bytes.len() % 2 != 0 {
        return Err(Error::DataConversionError(
            "Oracle national text has an odd byte length".to_string(),
        ));
    }
    let code_units = bytes
        .chunks_exact(2)
        .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]));
    char::decode_utf16(code_units)
        .collect::<std::result::Result<String, _>>()
        .map_err(|_| Error::DataConversionError("Oracle national text is invalid UTF-16".into()))
}

fn oracle_type_from_wire_code(code: u8) -> Result<crate::constants::OracleType> {
    crate::constants::OracleType::try_from(code).map_err(|_| Error::InvalidOracleType(code))
}

fn parse_type_name(type_name: &str, default_schema: &str) -> (String, String) {
    let parts: Vec<&str> = type_name.split('.').collect();
    match parts.len() {
        1 => (default_schema.to_uppercase(), parts[0].to_uppercase()),
        2 => (parts[0].to_uppercase(), parts[1].to_uppercase()),
        _ => {
            // Multiple dots - take first as schema, rest as name
            (parts[0].to_uppercase(), parts[1..].join(".").to_uppercase())
        }
    }
}

/// Convert an Oracle type name from data dictionary to OracleType enum
fn oracle_type_from_name(type_name: &str) -> crate::constants::OracleType {
    use crate::constants::OracleType;

    match type_name.to_uppercase().as_str() {
        "NUMBER" => OracleType::Number,
        "INTEGER" | "INT" | "SMALLINT" => OracleType::Number,
        "FLOAT" | "REAL" | "DOUBLE PRECISION" => OracleType::BinaryDouble,
        "BINARY_FLOAT" => OracleType::BinaryFloat,
        "BINARY_DOUBLE" => OracleType::BinaryDouble,
        "VARCHAR2" | "VARCHAR" | "NVARCHAR2" => OracleType::Varchar,
        "CHAR" | "NCHAR" => OracleType::Char,
        "DATE" => OracleType::Date,
        "TIMESTAMP" => OracleType::Timestamp,
        "TIMESTAMP WITH TIME ZONE" => OracleType::TimestampTz,
        "TIMESTAMP WITH LOCAL TIME ZONE" => OracleType::TimestampLtz,
        "RAW" => OracleType::Raw,
        "BLOB" => OracleType::Blob,
        "CLOB" | "NCLOB" => OracleType::Clob,
        "BOOLEAN" | "PL/SQL BOOLEAN" => OracleType::Boolean,
        "ROWID" | "UROWID" => OracleType::Rowid,
        "XMLTYPE" => OracleType::Varchar, // Treat XMLType as string for now
        _ => OracleType::Varchar,         // Default to VARCHAR for unknown types
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::WriteBuffer;
    use crate::constants::{ccap_value, uds_flags};
    use crate::row::Value;

    fn disconnected_connection(limits: WireLimits) -> Connection {
        let mut config = Config::default();
        config.wire_limits = limits;
        Connection {
            inner: Arc::new(Mutex::new(ConnectionInner::new_with_cache(0, limits))),
            config,
            closed: AtomicBool::new(false),
            id: 1,
        }
    }

    #[test]
    fn tls_resend_requests_a_fresh_tls_handshake() {
        assert_eq!(
            connect_resend_action(true, crate::constants::packet_flags::TLS_RENEG).unwrap(),
            ConnectResendAction::RenegotiateTls
        );
        assert_eq!(
            connect_resend_action(true, 0).unwrap(),
            ConnectResendAction::Replay
        );
    }

    #[test]
    fn plaintext_resend_rejects_a_tls_renegotiation_flag() {
        assert!(matches!(
            connect_resend_action(false, crate::constants::packet_flags::TLS_RENEG),
            Err(Error::ProtocolError(_))
        ));
    }

    fn success_error_info(ttc_field_version: u8) -> Vec<u8> {
        let mut buffer = WriteBuffer::new();
        buffer.write_ub4(0).unwrap(); // end-of-call status
        buffer.write_ub2(0).unwrap(); // end-to-end sequence
        buffer.write_ub4(0).unwrap(); // current row
        buffer.write_ub2(0).unwrap(); // short error number
        buffer.write_ub2(0).unwrap(); // array element error
        buffer.write_ub2(0).unwrap(); // array element error
        buffer.write_ub2(7).unwrap(); // cursor ID
        buffer.write_u8(0).unwrap(); // signed error position zero
        for _ in 0..6 {
            buffer.write_ub1(0).unwrap();
        }
        buffer.write_ub4(0).unwrap(); // rowid rba
        buffer.write_ub2(0).unwrap(); // rowid partition
        buffer.write_ub1(0).unwrap(); // rowid padding
        buffer.write_ub4(0).unwrap(); // rowid block
        buffer.write_ub2(0).unwrap(); // rowid slot
        buffer.write_ub4(0).unwrap(); // OS error
        buffer.write_ub1(0).unwrap(); // statement number
        buffer.write_ub1(0).unwrap(); // call number
        buffer.write_ub2(0).unwrap(); // padding
        buffer.write_ub4(0).unwrap(); // successful iterations
        buffer.write_ub4(0).unwrap(); // logical rowid length
        buffer.write_ub2(0).unwrap(); // batch errors
        buffer.write_ub4(0).unwrap(); // batch offsets
        buffer.write_ub2(0).unwrap(); // batch messages
        buffer.write_ub4(0).unwrap(); // extended error
        buffer.write_ub8(1).unwrap(); // row count
        if ttc_field_version >= ccap_value::FIELD_VERSION_20_1 {
            buffer.write_ub4(0).unwrap(); // SQL type
            buffer.write_ub4(0).unwrap(); // server checksum
        }
        buffer.as_slice().to_vec()
    }

    fn data_packet(payload: &[u8]) -> Vec<u8> {
        let length = PACKET_HEADER_SIZE + payload.len();
        let mut packet = Vec::with_capacity(length);
        packet.extend_from_slice(&(length as u16).to_be_bytes());
        packet.extend_from_slice(&[0, 0]);
        packet.push(PacketType::Data as u8);
        packet.extend_from_slice(&[0, 0, 0]);
        packet.extend_from_slice(payload);
        packet
    }

    fn write_row_header(buffer: &mut WriteBuffer, bit_vector: Option<&[u8]>) {
        buffer.write_u8(MessageType::RowHeader as u8).unwrap();
        buffer.write_u8(0).unwrap(); // flags
        buffer.write_ub2(0).unwrap(); // num requests
        buffer.write_ub4(0).unwrap(); // iteration number
        buffer.write_ub4(0).unwrap(); // num iterations
        buffer.write_ub2(0).unwrap(); // buffer length
        let num_bytes = bit_vector.map_or(0, <[u8]>::len);
        buffer.write_ub4(num_bytes as u32).unwrap();
        if let Some(bit_vector) = bit_vector {
            buffer.write_u8(num_bytes as u8).unwrap(); // repeated length
            buffer.write_bytes(bit_vector).unwrap();
        }
        buffer.write_ub4(0).unwrap(); // rxhrid outer length
    }

    fn describe_info_for_column(
        ttc_field_version: u8,
        oracle_type: OracleType,
        uds_metadata_flags: u32,
        vector: Option<(u32, u8, u8)>,
    ) -> Vec<u8> {
        let mut encoded = WriteBuffer::new();
        encoded.write_ub4(0).unwrap(); // max row size
        encoded.write_ub4(1).unwrap(); // number of columns
        encoded.write_u8(0).unwrap(); // describe flags
        encoded.write_u8(oracle_type as u8).unwrap();
        encoded.write_u8(0).unwrap(); // column flags
        encoded.write_u8(0).unwrap(); // precision
        encoded.write_u8(0).unwrap(); // scale
        encoded.write_ub4(3).unwrap(); // buffer size
        encoded.write_ub4(0).unwrap(); // max array elements
        encoded.write_ub8(0).unwrap(); // continuation flags
        encoded.write_ub4(0).unwrap(); // OID outer length
        encoded.write_ub2(0).unwrap(); // version
        encoded.write_ub2(0).unwrap(); // charset ID
        encoded.write_u8(1).unwrap(); // charset form
        encoded.write_ub4(3).unwrap(); // max size
        if ttc_field_version >= ccap_value::FIELD_VERSION_12_2 {
            encoded.write_ub4(0).unwrap(); // oaccolid
        }
        encoded.write_u8(1).unwrap(); // nullable
        encoded.write_u8(0).unwrap(); // v7 name length
        encoded.write_ub4(0).unwrap(); // name
        encoded.write_ub4(0).unwrap(); // schema
        encoded.write_ub4(0).unwrap(); // type name
        encoded.write_ub2(1).unwrap(); // column position
        encoded.write_ub4(uds_metadata_flags).unwrap();
        if ttc_field_version >= ccap_value::FIELD_VERSION_23_1 {
            encoded.write_ub4(0).unwrap(); // domain schema
            encoded.write_ub4(0).unwrap(); // domain name
        }
        if ttc_field_version >= 20 {
            encoded.write_ub4(0).unwrap(); // annotations
        }
        if ttc_field_version >= ccap_value::FIELD_VERSION_23_4 {
            let (dimensions, format, flags) = vector.unwrap_or_default();
            encoded.write_ub4(dimensions).unwrap();
            encoded.write_u8(format).unwrap();
            encoded.write_u8(flags).unwrap();
        }
        encoded.write_ub4(0).unwrap(); // current date
        for _ in 0..4 {
            encoded.write_ub4(0).unwrap(); // DCB fields
        }
        encoded.write_ub4(0).unwrap(); // dcbqcky
        encoded.as_slice().to_vec()
    }

    fn append_successful_query_end(buffer: &mut WriteBuffer, ttc_field_version: u8) {
        buffer.write_u8(MessageType::Error as u8).unwrap();
        buffer
            .write_bytes(&success_error_info(ttc_field_version))
            .unwrap();
    }

    #[test]
    fn test_query_options_default() {
        let opts = QueryOptions::default();
        assert_eq!(opts.prefetch_rows, 100);
        assert_eq!(opts.array_size, 100);
        assert!(!opts.auto_commit);
    }

    #[test]
    fn test_query_result_empty() {
        let result = QueryResult::empty();
        assert!(result.is_empty());
        assert_eq!(result.column_count(), 0);
        assert_eq!(result.row_count(), 0);
        assert!(result.first().is_none());
    }

    #[test]
    fn test_query_result_with_rows() {
        let columns = vec![ColumnInfo::new("ID", crate::constants::OracleType::Number)];
        let rows = vec![Row::new(vec![Value::Integer(1)])];

        let result = QueryResult {
            columns,
            rows,
            rows_affected: 0,
            has_more_rows: false,
            cursor_id: 1,
            response_packet_count: 1,
        };

        assert!(!result.is_empty());
        assert_eq!(result.column_count(), 1);
        assert_eq!(result.row_count(), 1);
        assert!(result.first().is_some());
        assert!(result.column_by_name("ID").is_some());
        assert!(result.column_by_name("id").is_some()); // Case insensitive
        assert_eq!(result.column_index("ID"), Some(0));
    }

    #[test]
    fn test_server_info_default() {
        let info = ServerInfo::default();
        assert!(info.version.is_empty());
        assert_eq!(info.session_id, 0);
    }

    #[test]
    fn test_connection_state_transitions() {
        assert_eq!(ConnectionState::Disconnected, ConnectionState::Disconnected);
        assert_ne!(ConnectionState::Connected, ConnectionState::Ready);
    }

    #[test]
    fn test_query_result_iterator() {
        let rows = vec![
            Row::new(vec![Value::Integer(1)]),
            Row::new(vec![Value::Integer(2)]),
        ];
        let result = QueryResult {
            columns: vec![],
            rows,
            rows_affected: 0,
            has_more_rows: false,
            cursor_id: 0,
            response_packet_count: 1,
        };

        let collected: Vec<_> = result.iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn test_query_result_into_iterator() {
        let rows = vec![
            Row::new(vec![Value::Integer(1)]),
            Row::new(vec![Value::Integer(2)]),
        ];
        let result = QueryResult {
            columns: vec![],
            rows,
            rows_affected: 0,
            has_more_rows: false,
            cursor_id: 0,
            response_packet_count: 1,
        };

        let collected: Vec<Row> = result.into_iter().collect();
        assert_eq!(collected.len(), 2);
    }

    #[test]
    fn oracle_19c_error_info_omits_20c_fields() {
        let connection = disconnected_connection(WireLimits::default());
        let bytes = success_error_info(ccap_value::FIELD_VERSION_19_1);
        let mut buffer = ReadBuffer::from_slice(&bytes);

        let parsed = connection
            .parse_error_info_with_rowcount_for_version(&mut buffer, ccap_value::FIELD_VERSION_19_1)
            .unwrap();

        assert_eq!(parsed, (0, None, 7, 1));
        assert_eq!(buffer.remaining(), 0);

        let mut wrong_version = ReadBuffer::from_slice(&bytes);
        assert!(matches!(
            connection.parse_error_info_with_rowcount_for_version(
                &mut wrong_version,
                ccap_value::FIELD_VERSION_20_1,
            ),
            Err(Error::BufferUnderflow { .. })
        ));
    }

    #[test]
    fn oracle_20c_error_info_includes_sql_type_and_checksum() {
        let connection = disconnected_connection(WireLimits::default());
        let bytes = success_error_info(ccap_value::FIELD_VERSION_20_1);
        let mut buffer = ReadBuffer::from_slice(&bytes);

        let parsed = connection
            .parse_error_info_with_rowcount_for_version(&mut buffer, ccap_value::FIELD_VERSION_20_1)
            .unwrap();

        assert_eq!(parsed, (0, None, 7, 1));
        assert_eq!(buffer.remaining(), 0);
    }

    #[test]
    fn dml_completion_uses_the_negotiated_19c_field_version() {
        let connection = disconnected_connection(WireLimits::default());
        let mut payload = WriteBuffer::new();
        payload.write_u16_be(0).unwrap();
        append_successful_query_end(&mut payload, ccap_value::FIELD_VERSION_19_1);

        let result = connection
            .parse_dml_response(payload.as_slice(), ccap_value::FIELD_VERSION_19_1)
            .unwrap();
        assert_eq!(result.cursor_id, 7);
        assert_eq!(result.rows_affected, 1);
    }

    #[test]
    fn multi_packet_payload_is_reassembled_with_a_hard_limit() {
        let limits = WireLimits {
            max_response_bytes: 6,
            ..WireLimits::default()
        };
        let inner = ConnectionInner::new_with_cache(0, limits);
        let mut target = Vec::new();

        inner
            .append_data_payload(&mut target, &data_packet(&[0, 0, 1, 2]))
            .unwrap();
        inner
            .append_data_payload(&mut target, &data_packet(&[0, 0, 3, 4]))
            .unwrap();
        assert_eq!(target, [0, 0, 1, 2, 3, 4]);
        assert!(matches!(
            inner.append_data_payload(&mut target, &data_packet(&[0, 0, 5])),
            Err(Error::LimitExceeded)
        ));
    }

    #[test]
    fn response_packet_count_has_a_hard_limit() {
        assert_eq!(
            increment_response_packet_count(MAX_RESPONSE_PACKETS - 1).unwrap(),
            MAX_RESPONSE_PACKETS
        );
        assert!(matches!(
            increment_response_packet_count(MAX_RESPONSE_PACKETS),
            Err(Error::LimitExceeded)
        ));
        assert!(matches!(
            increment_response_packet_count(usize::MAX),
            Err(Error::LimitExceeded)
        ));
    }

    #[test]
    fn scalar_value_limit_is_enforced_before_overflow_payload_is_read() {
        let limits = WireLimits {
            max_value_bytes: 4,
            ..WireLimits::default()
        };
        let connection = disconnected_connection(limits);
        let column = ColumnInfo::new("VALUE", crate::constants::OracleType::Varchar);
        let mut buffer = ReadBuffer::from_slice(&[
            crate::constants::length::LONG_INDICATOR,
            0x01,
            0x03,
            0x41,
            0x42,
            0x43,
            0x01,
            0x02,
            0x44,
            0x45,
            0x00,
        ]);

        assert!(matches!(
            connection.parse_column_value(&mut buffer, &column, &Capabilities::default()),
            Err(Error::LimitExceeded)
        ));
        assert_eq!(buffer.position(), 8);
        assert_eq!(buffer.remaining_bytes(), &[0x44, 0x45, 0x00]);
    }

    #[test]
    fn core_scalar_mode_rejects_other_types_before_wire_decode() {
        let mut connection = disconnected_connection(WireLimits::default());
        connection.config.value_decode_policy = ValueDecodePolicy::CoreScalar;

        for oracle_type in [
            OracleType::BinaryInteger,
            OracleType::Long,
            OracleType::Rowid,
            OracleType::LongRaw,
            OracleType::BinaryFloat,
            OracleType::BinaryDouble,
            OracleType::Clob,
            OracleType::Blob,
            OracleType::Bfile,
            OracleType::Json,
            OracleType::Vector,
            OracleType::Cursor,
            OracleType::Object,
            OracleType::TimestampTz,
            OracleType::TimestampLtz,
            OracleType::IntervalYm,
            OracleType::IntervalDs,
            OracleType::Urowid,
            OracleType::Boolean,
        ] {
            let column = ColumnInfo::new("VALUE", oracle_type);
            let mut buffer = ReadBuffer::from_slice(&[]);

            assert!(matches!(
                connection.parse_column_value(&mut buffer, &column, &Capabilities::default()),
                Err(Error::DataConversionError(_))
            ));
            assert_eq!(buffer.position(), 0);
        }

        let mut tagged_json = ColumnInfo::new("VALUE", OracleType::Varchar);
        tagged_json.is_json = true;
        let mut buffer = ReadBuffer::from_slice(&[]);
        assert!(matches!(
            connection.parse_column_value(&mut buffer, &tagged_json, &Capabilities::default()),
            Err(Error::DataConversionError(_))
        ));
        assert_eq!(buffer.position(), 0);

        for oracle_type in [
            OracleType::Number,
            OracleType::Date,
            OracleType::Timestamp,
            OracleType::Varchar,
            OracleType::Char,
            OracleType::Raw,
        ] {
            let column = ColumnInfo::new("VALUE", oracle_type);
            let mut buffer = ReadBuffer::from_slice(&[0]);
            let value = connection
                .parse_column_value(&mut buffer, &column, &Capabilities::default())
                .unwrap();
            assert!(matches!(value, Value::Null));
            assert_eq!(buffer.remaining(), 0);
        }

        let column = ColumnInfo::new("VALUE", OracleType::Varchar);
        let mut buffer = ReadBuffer::from_slice(&[1, b'A']);
        let value = connection
            .parse_column_value(&mut buffer, &column, &Capabilities::default())
            .unwrap();
        assert!(matches!(value, Value::String(value) if value == "A"));
        assert_eq!(buffer.remaining(), 0);
    }

    #[test]
    fn row_header_bit_vector_reuses_values_within_a_page() {
        let connection = disconnected_connection(WireLimits::default());
        let columns = vec![
            ColumnInfo::new("FIRST", OracleType::Varchar),
            ColumnInfo::new("SECOND", OracleType::Varchar),
        ];
        let caps = Capabilities {
            ttc_field_version: ccap_value::FIELD_VERSION_19_1,
            supports_end_of_response: false,
            ..Capabilities::default()
        };
        let mut encoded = WriteBuffer::new();
        encoded.write_u16_be(0).unwrap(); // data flags
        write_row_header(&mut encoded, None);
        encoded.write_u8(MessageType::RowData as u8).unwrap();
        encoded.write_bytes_with_length(Some(b"A")).unwrap();
        encoded.write_bytes_with_length(Some(b"B")).unwrap();
        write_row_header(&mut encoded, Some(&[0b0000_0001]));
        encoded.write_u8(MessageType::RowData as u8).unwrap();
        encoded.write_bytes_with_length(Some(b"C")).unwrap();
        append_successful_query_end(&mut encoded, caps.ttc_field_version);

        let result = connection
            .parse_query_response_with_columns(encoded.as_slice(), &caps, &columns)
            .unwrap();

        assert_eq!(result.rows.len(), 2);
        assert!(matches!(result.rows[0].get(0), Some(Value::String(value)) if value == "A"));
        assert!(matches!(result.rows[0].get(1), Some(Value::String(value)) if value == "B"));
        assert!(matches!(result.rows[1].get(0), Some(Value::String(value)) if value == "C"));
        assert!(matches!(result.rows[1].get(1), Some(Value::String(value)) if value == "B"));
    }

    #[test]
    fn first_continuation_row_can_reuse_the_previous_page() {
        let connection = disconnected_connection(WireLimits::default());
        let columns = vec![
            ColumnInfo::new("FIRST", OracleType::Varchar),
            ColumnInfo::new("SECOND", OracleType::Varchar),
        ];
        let previous = Row::new(vec![Value::String("A".into()), Value::String("B".into())]);
        let caps = Capabilities {
            ttc_field_version: ccap_value::FIELD_VERSION_19_1,
            supports_end_of_response: false,
            ..Capabilities::default()
        };
        let mut encoded = WriteBuffer::new();
        encoded.write_u16_be(0).unwrap(); // data flags
        write_row_header(&mut encoded, Some(&[0]));
        encoded.write_u8(MessageType::RowData as u8).unwrap();
        append_successful_query_end(&mut encoded, caps.ttc_field_version);

        let result = connection
            .parse_query_response_with_columns_and_previous(
                encoded.as_slice(),
                &caps,
                &columns,
                Some(previous.values()),
            )
            .unwrap();

        assert_eq!(result.rows.len(), 1);
        assert!(matches!(result.rows[0].get(0), Some(Value::String(value)) if value == "A"));
        assert!(matches!(result.rows[0].get(1), Some(Value::String(value)) if value == "B"));
    }

    #[test]
    fn duplicate_without_a_previous_row_fails_instead_of_becoming_null() {
        let connection = disconnected_connection(WireLimits::default());
        let columns = vec![ColumnInfo::new("VALUE", OracleType::Varchar)];
        let mut buffer = ReadBuffer::from_slice(&[]);

        assert!(matches!(
            connection.parse_row_data_with_bitvector(
                &mut buffer,
                &columns,
                &Capabilities::default(),
                Some(&[0]),
                None,
            ),
            Err(Error::Protocol(_))
        ));
        assert_eq!(buffer.position(), 0);
    }

    #[test]
    fn row_header_bit_vector_width_must_match_the_schema() {
        let connection = disconnected_connection(WireLimits::default());
        let mut encoded = WriteBuffer::new();
        write_row_header(&mut encoded, Some(&[0, 0]));
        let mut buffer = ReadBuffer::from_slice(&encoded.as_slice()[1..]);

        assert!(matches!(
            connection.parse_row_header(&mut buffer, 2),
            Err(Error::Protocol(_))
        ));
        assert_eq!(buffer.remaining_bytes(), &[2, 0, 0, 0]);
    }

    #[test]
    fn return_parameter_pairs_use_outer_and_inner_lengths() {
        let connection = disconnected_connection(WireLimits::default());
        let mut encoded = WriteBuffer::new();
        encoded.write_ub2(0).unwrap(); // al8o4l
        encoded.write_ub2(0).unwrap(); // al8txl
        encoded.write_ub2(1).unwrap(); // key/value pairs
        encoded.write_ub2(3).unwrap(); // outer text length
        encoded.write_bytes_with_length(Some(b"ABC")).unwrap();
        encoded.write_ub2(2).unwrap(); // outer binary length
        encoded.write_bytes_with_length(Some(b"DE")).unwrap();
        encoded.write_ub2(7).unwrap(); // keyword
        encoded.write_ub2(0).unwrap(); // registration
        let bytes = encoded.as_slice().to_vec();
        let mut buffer = ReadBuffer::from_slice(&bytes);

        connection.parse_return_parameters(&mut buffer).unwrap();

        assert_eq!(buffer.remaining(), 0);
    }

    #[test]
    fn return_parameter_outer_length_is_admitted_before_inner_value() {
        let limits = WireLimits {
            max_value_bytes: 4,
            ..WireLimits::default()
        };
        let connection = disconnected_connection(limits);
        let mut encoded = WriteBuffer::new();
        encoded.write_ub2(0).unwrap(); // al8o4l
        encoded.write_ub2(0).unwrap(); // al8txl
        encoded.write_ub2(1).unwrap(); // key/value pairs
        encoded.write_ub2(5).unwrap(); // oversized outer text length
        let bytes = encoded.as_slice().to_vec();
        let mut buffer = ReadBuffer::from_slice(&bytes);

        assert!(matches!(
            connection.parse_return_parameters(&mut buffer),
            Err(Error::LimitExceeded)
        ));
        assert_eq!(buffer.remaining(), 0);
    }

    #[test]
    fn describe_oid_uses_outer_and_inner_lengths() {
        let connection = disconnected_connection(WireLimits::default());
        let mut encoded = WriteBuffer::new();
        encoded.write_ub4(0).unwrap(); // max row size
        encoded.write_ub4(1).unwrap(); // number of columns
        encoded.write_u8(0).unwrap(); // describe flags
        encoded.write_u8(OracleType::Varchar as u8).unwrap();
        encoded.write_u8(0).unwrap(); // column flags
        encoded.write_u8(0).unwrap(); // precision
        encoded.write_u8(0).unwrap(); // scale
        encoded.write_ub4(3).unwrap(); // buffer size
        encoded.write_ub4(0).unwrap(); // max array elements
        encoded.write_ub8(0).unwrap(); // continuation flags
        encoded.write_ub4(3).unwrap(); // outer OID length
        encoded.write_bytes_with_length(Some(b"OID")).unwrap();
        encoded.write_ub2(0).unwrap(); // version
        encoded.write_ub2(0).unwrap(); // charset ID
        encoded.write_u8(1).unwrap(); // charset form
        encoded.write_ub4(3).unwrap(); // max size
        encoded.write_u8(1).unwrap(); // nullable
        encoded.write_u8(0).unwrap(); // v7 name length
        encoded.write_ub4(0).unwrap(); // name
        encoded.write_ub4(0).unwrap(); // schema
        encoded.write_ub4(0).unwrap(); // type name
        encoded.write_ub2(1).unwrap(); // column position
        encoded.write_ub4(0).unwrap(); // UDS flags
        encoded.write_ub4(0).unwrap(); // current date
        for _ in 0..4 {
            encoded.write_ub4(0).unwrap(); // DCB fields
        }
        encoded.write_ub4(0).unwrap(); // dcbqcky
        let bytes = encoded.as_slice().to_vec();
        let mut buffer = ReadBuffer::from_slice(&bytes);

        let columns = connection.parse_describe_info(&mut buffer, 0).unwrap();

        assert_eq!(columns.len(), 1);
        assert_eq!(columns[0].oracle_type, OracleType::Varchar);
        assert_eq!(buffer.remaining(), 0);
    }

    #[test]
    fn describe_metadata_preserves_semantic_tags_before_value_decode() {
        let mut connection = disconnected_connection(WireLimits::default());
        connection.config.value_decode_policy = ValueDecodePolicy::CoreScalar;
        let cases = [
            (
                ccap_value::FIELD_VERSION_19_1,
                OracleType::Varchar,
                uds_flags::IS_JSON,
                None,
                true,
                false,
                None,
                None,
            ),
            (
                ccap_value::FIELD_VERSION_19_1,
                OracleType::Raw,
                uds_flags::IS_OSON,
                None,
                false,
                true,
                None,
                None,
            ),
            (
                ccap_value::FIELD_VERSION_23_4,
                OracleType::Raw,
                0,
                Some((3, 2, 0)),
                false,
                false,
                Some(3),
                Some(2),
            ),
        ];

        for (
            field_version,
            oracle_type,
            uds_metadata_flags,
            vector,
            is_json,
            is_oson,
            vector_dimensions,
            vector_format,
        ) in cases
        {
            let bytes =
                describe_info_for_column(field_version, oracle_type, uds_metadata_flags, vector);
            let mut metadata_buffer = ReadBuffer::from_slice(&bytes);
            let columns = connection
                .parse_describe_info(&mut metadata_buffer, field_version)
                .unwrap();
            let column = &columns[0];

            assert_eq!(column.is_json, is_json);
            assert_eq!(column.is_oson, is_oson);
            assert_eq!(column.vector_dimensions, vector_dimensions);
            assert_eq!(column.vector_format, vector_format);
            assert_eq!(metadata_buffer.remaining(), 0);

            let mut value_buffer = ReadBuffer::from_slice(&[1, b'X']);
            assert!(matches!(
                connection.parse_column_value(&mut value_buffer, column, &Capabilities::default(),),
                Err(Error::DataConversionError(_))
            ));
            assert_eq!(value_buffer.position(), 0);
        }
    }

    #[test]
    fn object_identifiers_use_outer_and_inner_lengths() {
        let connection = disconnected_connection(WireLimits::default());
        let column = ColumnInfo::new("VALUE", OracleType::Object);
        let mut encoded = WriteBuffer::new();
        encoded.write_ub4(3).unwrap(); // outer type OID length
        encoded.write_bytes_with_length(Some(b"OID")).unwrap();
        encoded.write_ub4(0).unwrap(); // object OID
        encoded.write_ub4(0).unwrap(); // snapshot
        encoded.write_ub2(0).unwrap(); // version
        encoded.write_ub4(0).unwrap(); // packed data length
        encoded.write_ub2(0).unwrap(); // flags
        let bytes = encoded.as_slice().to_vec();
        let mut buffer = ReadBuffer::from_slice(&bytes);

        let value = connection
            .parse_column_value(&mut buffer, &column, &Capabilities::default())
            .unwrap();

        assert!(matches!(value, Value::Null));
        assert_eq!(buffer.remaining(), 0);
    }

    #[test]
    fn object_data_length_is_admitted_before_flags_and_payload() {
        let limits = WireLimits {
            max_value_bytes: 4,
            ..WireLimits::default()
        };
        let connection = disconnected_connection(limits);
        let column = ColumnInfo::new("VALUE", OracleType::Object);
        let mut encoded = WriteBuffer::new();
        encoded.write_ub4(0).unwrap(); // type OID
        encoded.write_ub4(0).unwrap(); // object OID
        encoded.write_ub4(0).unwrap(); // snapshot
        encoded.write_ub2(0).unwrap(); // version
        encoded.write_ub4(5).unwrap(); // oversized packed data length
        let bytes = encoded.as_slice().to_vec();
        let mut buffer = ReadBuffer::from_slice(&bytes);

        assert!(matches!(
            connection.parse_column_value(&mut buffer, &column, &Capabilities::default()),
            Err(Error::LimitExceeded)
        ));
        assert_eq!(buffer.remaining(), 0);
    }

    #[test]
    fn lob_value_limit_is_enforced_before_payload_is_read() {
        let limits = WireLimits {
            max_value_bytes: 4,
            ..WireLimits::default()
        };
        let connection = disconnected_connection(limits);
        let column = ColumnInfo::new("VALUE", OracleType::Blob);
        let mut encoded = WriteBuffer::new();
        encoded.write_ub4(1).unwrap(); // non-null LOB
        encoded.write_ub8(5).unwrap(); // LOB size
        encoded.write_ub4(0).unwrap(); // chunk size
        encoded.write_bytes_with_length(Some(b"ABCDE")).unwrap();
        let bytes = encoded.as_slice().to_vec();
        let mut buffer = ReadBuffer::from_slice(&bytes);

        assert!(matches!(
            connection.parse_column_value(&mut buffer, &column, &Capabilities::default()),
            Err(Error::LimitExceeded)
        ));
        assert_eq!(buffer.remaining_bytes(), b"ABCDE");
    }

    #[test]
    fn query_error_info_reassembles_at_every_packet_boundary() {
        let connection = disconnected_connection(WireLimits::default());
        let mut caps = Capabilities::default();
        caps.ttc_field_version = ccap_value::FIELD_VERSION_19_1;
        caps.supports_end_of_response = false;
        let mut response = vec![0, 0, MessageType::Error as u8];
        response.extend_from_slice(&success_error_info(caps.ttc_field_version));

        for split in 2..response.len() {
            let inner = ConnectionInner::new_with_cache(0, WireLimits::default());
            let mut payload = Vec::new();
            inner
                .append_data_payload(&mut payload, &data_packet(&response[..split]))
                .unwrap();
            assert!(matches!(
                connection.parse_query_response(&payload, &caps),
                Err(Error::BufferUnderflow { .. } | Error::IncompleteResponse)
            ));

            let mut continuation = vec![0, 0];
            continuation.extend_from_slice(&response[split..]);
            inner
                .append_data_payload(&mut payload, &data_packet(&continuation))
                .unwrap();
            let result = connection.parse_query_response(&payload, &caps).unwrap();
            assert_eq!(result.cursor_id, 7);
            assert_eq!(result.rows_affected, 1);
            assert!(result.has_more_rows);
        }
    }

    #[test]
    fn modern_query_response_validates_non_pipelined_token() {
        let connection = disconnected_connection(WireLimits::default());
        let mut caps = Capabilities::new();
        caps.ttc_field_version = ccap_value::FIELD_VERSION_23_4;
        let mut payload = WriteBuffer::new();
        payload.write_u16_be(0).unwrap();
        payload.write_u8(MessageType::Token as u8).unwrap();
        payload.write_ub8(NON_PIPELINED_TOKEN_NUMBER).unwrap();
        append_successful_query_end(&mut payload, caps.ttc_field_version);

        let result = connection
            .parse_query_response(payload.as_slice(), &caps)
            .unwrap();
        assert_eq!(result.cursor_id, 7);
        assert_eq!(result.rows_affected, 1);
    }

    #[test]
    fn modern_query_response_rejects_mismatched_token_before_completion() {
        let connection = disconnected_connection(WireLimits::default());
        let mut caps = Capabilities::new();
        caps.ttc_field_version = ccap_value::FIELD_VERSION_23_4;
        let mut payload = WriteBuffer::new();
        payload.write_u16_be(0).unwrap();
        payload.write_u8(MessageType::Token as u8).unwrap();
        payload.write_ub8(7).unwrap();
        append_successful_query_end(&mut payload, caps.ttc_field_version);

        let error = connection
            .parse_query_response(payload.as_slice(), &caps)
            .unwrap_err();
        assert!(matches!(error, Error::Protocol(_)));
        assert!(!error.to_string().contains('7'));
    }

    #[test]
    fn terminal_scanner_skips_a_complete_token_message() {
        let inner = ConnectionInner::new_with_cache(0, WireLimits::default());
        let mut messages = WriteBuffer::new();
        messages.write_u8(MessageType::Token as u8).unwrap();
        messages.write_ub8(NON_PIPELINED_TOKEN_NUMBER).unwrap();
        messages.write_u8(MessageType::EndOfResponse as u8).unwrap();

        assert!(inner.scan_for_terminal_message(messages.as_slice()));
        assert!(!inner.scan_for_terminal_message(&[MessageType::Token as u8, 2, 1,]));
    }

    #[test]
    fn simple_function_response_consumes_token_before_completion() {
        let connection = disconnected_connection(WireLimits::default());
        let mut payload = WriteBuffer::new();
        payload.write_u16_be(0).unwrap();
        payload.write_u8(MessageType::Token as u8).unwrap();
        payload.write_ub8(NON_PIPELINED_TOKEN_NUMBER).unwrap();
        append_successful_query_end(&mut payload, ccap_value::FIELD_VERSION_19_1);

        connection
            .parse_simple_function_response(payload.as_slice())
            .unwrap();
    }

    #[tokio::test]
    async fn dns_resolution_failure_is_distinct_and_redacted() {
        let error = connect_tcp("private\0host", 1521).await.unwrap_err();

        assert!(matches!(error, Error::Dns));
        assert_eq!(error.to_string(), "DNS resolution failed");
        assert!(!error.to_string().contains("private"));
    }

    #[test]
    fn database_version_is_derived_from_bounded_server_banner() {
        assert_eq!(
            database_version_from_banner(
                "Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production"
            )
            .as_deref(),
            Some("19.0.0.0.0")
        );
        assert_eq!(
            database_version_from_banner("Oracle Database 19c").as_deref(),
            Some("19c")
        );
        assert_eq!(
            database_version_from_banner("Oracle Database 23ai").as_deref(),
            Some("23ai")
        );
        assert_eq!(database_version_from_banner("Oracle Database"), None);
    }

    #[test]
    fn national_text_requires_well_formed_utf16be() {
        assert_eq!(
            decode_utf16_be(&[0, b'A', 0x20, 0xac]).unwrap(),
            "A\u{20ac}"
        );
        assert!(matches!(
            decode_utf16_be(&[0]),
            Err(Error::DataConversionError(_))
        ));
        assert!(matches!(
            decode_utf16_be(&[0xd8, 0x00]),
            Err(Error::DataConversionError(_))
        ));
    }

    #[test]
    fn unknown_describe_type_does_not_fall_back_to_text() {
        assert!(matches!(
            oracle_type_from_wire_code(u8::MAX),
            Err(Error::InvalidOracleType(u8::MAX))
        ));
    }
}
