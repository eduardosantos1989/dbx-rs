use crate::buffer::ReadBuffer;
use crate::error::{Error, Result};

const MAX_ELEMENTS: u16 = 4096;

const QUERY_CACHE_INVALIDATION: u8 = 1;
const OS_PID_MTS: u8 = 2;
const TRACE_EVENT: u8 = 3;
const SESSION_RETURN: u8 = 4;
const SYNC: u8 = 5;
const LOGICAL_TRANSACTION_ID: u8 = 7;
const AC_REPLAY_CONTEXT: u8 = 8;
const EXTENDED_SYNC: u8 = 9;
const SESSION_SIGNATURE: u8 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SessionIdentity {
    pub(crate) session_id: u32,
    pub(crate) serial_number: u16,
}

fn check_element_count(count: u16) -> Result<()> {
    if count > MAX_ELEMENTS {
        Err(Error::LimitExceeded)
    } else {
        Ok(())
    }
}

fn skip_two_length_value(buf: &mut ReadBuffer, outer_length: u16) -> Result<()> {
    if outer_length > 0 {
        buf.skip_bytes_with_length_bounded(outer_length as usize)?;
    }
    Ok(())
}

fn skip_keyword_value_pairs(buf: &mut ReadBuffer, count: u16) -> Result<()> {
    check_element_count(count)?;
    for _ in 0..count {
        let text_length = buf.read_ub2()?;
        skip_two_length_value(buf, text_length)?;
        let binary_length = buf.read_ub2()?;
        skip_two_length_value(buf, binary_length)?;
        buf.skip_ub2()?; // keyword number
    }
    Ok(())
}

pub(crate) fn parse_server_side_piggyback(
    buf: &mut ReadBuffer,
) -> Result<Option<SessionIdentity>> {
    let opcode = buf.read_ub1()?;
    match opcode {
        QUERY_CACHE_INVALIDATION | TRACE_EVENT => Ok(None),
        OS_PID_MTS => {
            let outer_length = buf.read_ub2()?;
            skip_two_length_value(buf, outer_length)?;
            Ok(None)
        }
        SYNC => {
            buf.skip_ub2()?; // number of data types
            buf.skip_ub1()?; // data-type byte length
            let count = buf.read_ub2()?;
            if count > 0 {
                buf.skip_ub1()?; // element byte length
            }
            skip_keyword_value_pairs(buf, count)?;
            buf.skip_ub4()?; // overall flags
            Ok(None)
        }
        EXTENDED_SYNC => {
            buf.skip_ub2()?; // number of data types
            buf.skip_ub1()?; // data-type byte length
            Ok(None)
        }
        LOGICAL_TRANSACTION_ID => {
            buf.skip_bytes_with_length_bounded(buf.remaining())?;
            Ok(None)
        }
        AC_REPLAY_CONTEXT => {
            buf.skip_ub2()?; // number of data types
            buf.skip_ub1()?; // data-type byte length
            buf.skip_ub4()?; // flags
            buf.skip_ub4()?; // error code
            buf.skip_ub1()?; // queue
            let outer_length = buf.read_ub4()? as usize;
            if outer_length > 0 {
                buf.skip_bytes_with_length_bounded(outer_length)?;
            }
            Ok(None)
        }
        SESSION_RETURN => {
            buf.skip_ub2()?; // number of data types
            buf.skip_ub1()?; // data-type byte length
            let count = buf.read_ub2()?;
            check_element_count(count)?;
            if count > 0 {
                buf.skip_ub1()?; // element byte length
                for _ in 0..count {
                    let key_length = buf.read_ub2()?;
                    skip_two_length_value(buf, key_length)?;
                    let value_length = buf.read_ub2()?;
                    skip_two_length_value(buf, value_length)?;
                    buf.skip_ub2()?; // element flags
                }
            }
            buf.skip_ub4()?; // session flags
            Ok(Some(SessionIdentity {
                session_id: buf.read_ub4()?,
                serial_number: buf.read_ub2()?,
            }))
        }
        SESSION_SIGNATURE => {
            buf.skip_ub2()?; // number of data types
            buf.skip_ub1()?; // data-type byte length
            buf.skip_ub8()?; // signature flags
            buf.skip_ub8()?; // client signature
            buf.skip_ub8()?; // server signature
            Ok(None)
        }
        _ => Err(Error::Protocol(format!(
            "unsupported Oracle server-side piggyback opcode {opcode}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::WriteBuffer;

    #[test]
    fn session_return_extracts_identity() {
        let mut encoded = WriteBuffer::new();
        encoded.write_ub1(SESSION_RETURN).unwrap();
        encoded.write_ub2(0).unwrap();
        encoded.write_ub1(0).unwrap();
        encoded.write_ub2(0).unwrap();
        encoded.write_ub4(0).unwrap();
        encoded.write_ub4(42).unwrap();
        encoded.write_ub2(7).unwrap();
        let mut buf = ReadBuffer::from_slice(encoded.as_slice());

        assert_eq!(
            parse_server_side_piggyback(&mut buf).unwrap(),
            Some(SessionIdentity {
                session_id: 42,
                serial_number: 7,
            })
        );
        assert_eq!(buf.remaining(), 0);
    }

    #[test]
    fn unknown_opcode_fails_closed() {
        let mut encoded = WriteBuffer::new();
        encoded.write_ub1(255).unwrap();
        let mut buf = ReadBuffer::from_slice(encoded.as_slice());

        assert!(matches!(
            parse_server_side_piggyback(&mut buf),
            Err(Error::Protocol(_))
        ));
    }
}
