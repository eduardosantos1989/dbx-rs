use crate::buffer::{ReadBuffer, WriteBuffer};
use crate::capabilities::Capabilities;
use crate::constants::ccap_value;
use crate::error::{Error, Result};

pub(crate) const NON_PIPELINED_TOKEN_NUMBER: u64 = 0;

pub(crate) fn write_request_token(
    buf: &mut WriteBuffer,
    caps: &Capabilities,
    token_number: u64,
) -> Result<()> {
    if caps.ttc_field_version >= ccap_value::FIELD_VERSION_23_1_EXT_1 {
        buf.write_ub8(token_number)?;
    }
    Ok(())
}

pub(crate) fn validate_response_token(
    buf: &mut ReadBuffer,
    expected_token_number: u64,
) -> Result<()> {
    let token_number = buf.read_ub8()?;
    if token_number != expected_token_number {
        return Err(Error::Protocol(
            "TTC response token did not match its request".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_token_is_version_gated() {
        let mut caps = Capabilities::new();
        caps.ttc_field_version = ccap_value::FIELD_VERSION_23_1;
        let mut encoded = WriteBuffer::new();
        write_request_token(&mut encoded, &caps, NON_PIPELINED_TOKEN_NUMBER).unwrap();
        assert!(encoded.as_slice().is_empty());

        caps.ttc_field_version = ccap_value::FIELD_VERSION_23_1_EXT_1;
        write_request_token(&mut encoded, &caps, NON_PIPELINED_TOKEN_NUMBER).unwrap();
        assert_eq!(encoded.as_slice(), &[0]);
    }

    #[test]
    fn response_token_must_match_without_exposing_its_value() {
        let mut encoded = WriteBuffer::new();
        encoded.write_ub8(7).unwrap();
        let mut response = ReadBuffer::from_slice(encoded.as_slice());

        let error = validate_response_token(&mut response, NON_PIPELINED_TOKEN_NUMBER).unwrap_err();
        assert!(matches!(error, Error::Protocol(_)));
        assert!(!error.to_string().contains('7'));
        assert_eq!(response.remaining(), 0);
    }

    #[test]
    fn truncated_response_token_fails_closed() {
        let mut response = ReadBuffer::from_slice(&[2, 1]);
        assert!(matches!(
            validate_response_token(&mut response, NON_PIPELINED_TOKEN_NUMBER),
            Err(Error::BufferUnderflow {
                needed: 2,
                available: 1
            })
        ));
    }
}
