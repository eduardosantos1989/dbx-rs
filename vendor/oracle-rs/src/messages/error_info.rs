use crate::buffer::ReadBuffer;
use crate::constants::ccap_value;
use crate::error::Result;

pub(crate) fn parse_error_info_with_rowcount_for_version(
    buf: &mut ReadBuffer,
    ttc_field_version: u8,
) -> Result<(u32, Option<String>, u16, u64)> {
    buf.skip_ub4()?; // end-of-call status
    buf.skip_ub2()?; // end-to-end sequence
    buf.skip_ub4()?; // current row number
    buf.skip_ub2()?; // short error number
    buf.skip_ub2()?; // array element error
    buf.skip_ub2()?; // array element error
    let cursor_id = buf.read_ub2()?;
    buf.read_sb2()?; // error position
    for _ in 0..6 {
        buf.skip_ub1()?;
    }

    buf.skip_ub4()?; // rowid rba
    buf.skip_ub2()?; // rowid partition ID
    buf.skip_ub1()?; // rowid padding
    buf.skip_ub4()?; // rowid block number
    buf.skip_ub2()?; // rowid slot number
    buf.skip_ub4()?; // OS error
    buf.skip_ub1()?; // statement number
    buf.skip_ub1()?; // call number
    buf.skip_ub2()?; // padding
    buf.skip_ub4()?; // successful iterations

    let logical_rowid_len = buf.read_ub4()?;
    if logical_rowid_len > 0 {
        buf.skip_raw_bytes_chunked()?;
    }

    let num_batch_errors = buf.read_ub2()?;
    if num_batch_errors > 0 {
        let first_byte = buf.read_u8()?;
        for _ in 0..num_batch_errors {
            if first_byte == crate::constants::length::LONG_INDICATOR {
                buf.skip_ub4()?;
            }
            buf.skip_ub2()?;
        }
        if first_byte == crate::constants::length::LONG_INDICATOR {
            buf.skip(1)?;
        }
    }

    let num_offsets = buf.read_ub4()?;
    if num_offsets > 0 {
        let first_byte = buf.read_u8()?;
        for _ in 0..num_offsets {
            if first_byte == crate::constants::length::LONG_INDICATOR {
                buf.skip_ub4()?;
            }
            buf.skip_ub4()?;
        }
        if first_byte == crate::constants::length::LONG_INDICATOR {
            buf.skip(1)?;
        }
    }

    let num_batch_messages = buf.read_ub2()?;
    if num_batch_messages > 0 {
        buf.skip(1)?; // packed size
        for _ in 0..num_batch_messages {
            buf.skip_ub2()?; // chunk length
            buf.read_string_with_length()?;
            buf.skip(2)?; // end marker
        }
    }

    let error_code = buf.read_ub4()?;
    let row_count = buf.read_ub8()?;
    if ttc_field_version >= ccap_value::FIELD_VERSION_20_1 {
        buf.skip_ub4()?; // SQL type
        buf.skip_ub4()?; // server checksum
    }
    let error_message = if error_code == 0 {
        None
    } else {
        buf.read_string_with_length()?
            .map(|message| message.trim().to_owned())
    };

    Ok((error_code, error_message, cursor_id, row_count))
}
