use std::fmt;

use serde::{Deserialize, Serialize};

macro_rules! opaque_identity {
    ($name:ident, $length:expr, $label:literal) => {
        #[derive(Clone, Copy, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        pub struct $name([u8; $length]);

        impl $name {
            #[must_use]
            pub const fn new(bytes: [u8; $length]) -> Self {
                Self(bytes)
            }

            #[must_use]
            pub const fn into_bytes(self) -> [u8; $length] {
                self.0
            }

            pub(crate) const fn as_bytes(&self) -> &[u8; $length] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!($label, "([REDACTED])"))
            }
        }
    };
}

opaque_identity!(InputKey, 32, "InputKey");
opaque_identity!(Fingerprint, 32, "Fingerprint");
opaque_identity!(BatchId, 16, "BatchId");
opaque_identity!(SegmentId, 16, "SegmentId");

pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

pub(crate) fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 || !value.bytes().all(is_lower_hex) {
        return None;
    }
    let mut decoded = [0_u8; N];
    for (index, output) in decoded.iter_mut().enumerate() {
        let high = hex_value(value.as_bytes()[index * 2])?;
        let low = hex_value(value.as_bytes()[index * 2 + 1])?;
        *output = (high << 4) | low;
    }
    Some(decoded)
}

const fn is_lower_hex(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}
