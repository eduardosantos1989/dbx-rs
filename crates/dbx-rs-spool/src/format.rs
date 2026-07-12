use std::fs::File;
use std::io::{BufReader, Read, Write};

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::digest::{Context, SHA256};
use ring::hkdf;

use crate::error::SpoolError;
use crate::identity::{BatchId, Fingerprint, InputKey, SegmentId};
use crate::key::{KEY_BYTES, KEY_ID_BYTES, SpoolKey};
use crate::model::{SegmentHeader, SegmentSummary};

pub(crate) const MAGIC: &[u8; 8] = b"DBXRSSPL";
pub(crate) const FORMAT_VERSION: u16 = 1;
const SALT_BYTES: usize = 32;
pub(crate) const PREFIX_BYTES: usize = MAGIC.len() + 2 + KEY_ID_BYTES + SALT_BYTES + 16;
const FRAME_PREFIX_BYTES: u64 = 4 + 8;
const HEADER_PAYLOAD_BYTES: usize = 32 + 32 + 8 + 16 + 8 + 8 + 8;
const FOOTER_PAYLOAD_BYTES: usize = 8 + 8 + 32;
const FRAME_HEADER: u8 = 1;
const FRAME_EVENT: u8 = 2;
const FRAME_FOOTER: u8 = 3;

pub(crate) struct SegmentEncoder {
    file: File,
    key: LessSafeKey,
    prefix: [u8; PREFIX_BYTES],
    next_sequence: u64,
    position: u64,
    limit: u64,
    event_count: u64,
    plaintext_bytes: u64,
    digest: Context,
}

impl SegmentEncoder {
    pub(crate) fn start(
        mut file: File,
        spool_key: &SpoolKey,
        salt: [u8; SALT_BYTES],
        segment_id: SegmentId,
        header: SegmentHeader,
        limit: u64,
    ) -> Result<Self, SpoolError> {
        let prefix = encode_prefix(spool_key.id, salt, segment_id);
        let key = derive_segment_key(&spool_key.bytes, &salt, segment_id)?;
        file.write_all(&prefix).map_err(|error| {
            SpoolError::io(
                "DBX-RS-SPOOL-FORMAT-0001",
                "segment_write",
                "failed to write a spool prefix",
                &error,
            )
        })?;
        let mut encoder = Self {
            file,
            key,
            prefix,
            next_sequence: 0,
            position: PREFIX_BYTES as u64,
            limit,
            event_count: 0,
            plaintext_bytes: 0,
            digest: Context::new(&SHA256),
        };
        let header_payload = encode_header(header);
        encoder.write_typed_frame(FRAME_HEADER, &header_payload, false)?;
        if encoder
            .position
            .checked_add(minimum_footer_frame_bytes())
            .is_none_or(|required| required > limit)
        {
            return Err(SpoolError::new(
                "DBX-RS-SPOOL-LIMIT-0002",
                "segment_begin",
                "spool segment limit cannot hold its metadata",
            ));
        }
        encoder.file.sync_all().map_err(|error| {
            SpoolError::io(
                "DBX-RS-SPOOL-FORMAT-0002",
                "segment_sync",
                "failed to synchronize an open spool segment",
                &error,
            )
        })?;
        Ok(encoder)
    }

    pub(crate) fn append_event(&mut self, event: &[u8]) -> Result<(), SpoolError> {
        if event.is_empty() {
            return Err(SpoolError::new(
                "DBX-RS-SPOOL-FORMAT-0003",
                "event_append",
                "spool events cannot be empty",
            ));
        }
        let frame_bytes = encoded_frame_bytes(event.len().checked_add(1).ok_or_else(|| {
            SpoolError::new(
                "DBX-RS-SPOOL-LIMIT-0003",
                "event_append",
                "spool event length overflowed",
            )
        })?)?;
        let required = self
            .position
            .checked_add(frame_bytes)
            .and_then(|position| position.checked_add(minimum_footer_frame_bytes()))
            .ok_or_else(|| {
                SpoolError::new(
                    "DBX-RS-SPOOL-LIMIT-0003",
                    "event_append",
                    "spool event length overflowed",
                )
            })?;
        if required > self.limit {
            return Err(SpoolError::new(
                "DBX-RS-SPOOL-LIMIT-0004",
                "event_append",
                "spool segment limit would be exceeded",
            ));
        }

        let next_event_count = self.event_count.checked_add(1).ok_or_else(|| {
            SpoolError::new(
                "DBX-RS-SPOOL-LIMIT-0005",
                "event_append",
                "spool event count overflowed",
            )
        })?;
        let event_bytes = u64::try_from(event.len()).map_err(|_| {
            SpoolError::new(
                "DBX-RS-SPOOL-LIMIT-0006",
                "event_append",
                "spool plaintext byte count overflowed",
            )
        })?;
        let next_plaintext_bytes =
            self.plaintext_bytes
                .checked_add(event_bytes)
                .ok_or_else(|| {
                    SpoolError::new(
                        "DBX-RS-SPOOL-LIMIT-0006",
                        "event_append",
                        "spool plaintext byte count overflowed",
                    )
                })?;
        self.write_typed_frame(FRAME_EVENT, event, true)?;
        self.event_count = next_event_count;
        self.plaintext_bytes = next_plaintext_bytes;
        self.digest.update(&event_bytes.to_be_bytes());
        self.digest.update(event);
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<(File, SegmentSummary, u64), SpoolError> {
        let digest = self.digest.clone().finish();
        let mut stream_digest = [0_u8; 32];
        stream_digest.copy_from_slice(digest.as_ref());
        let summary = SegmentSummary {
            event_count: self.event_count,
            plaintext_bytes: self.plaintext_bytes,
            stream_digest,
        };
        let footer = encode_footer(summary);
        self.write_typed_frame(FRAME_FOOTER, &footer, false)?;
        self.file.sync_all().map_err(|error| {
            SpoolError::io(
                "DBX-RS-SPOOL-FORMAT-0004",
                "segment_sync",
                "failed to synchronize a sealed spool segment",
                &error,
            )
        })?;
        Ok((self.file, summary, self.position))
    }

    fn write_typed_frame(
        &mut self,
        frame_type: u8,
        payload: &[u8],
        payload_is_event: bool,
    ) -> Result<(), SpoolError> {
        let mut plaintext = Vec::with_capacity(payload.len().saturating_add(1));
        plaintext.push(frame_type);
        plaintext.extend_from_slice(payload);
        let cipher_length = plaintext
            .len()
            .checked_add(aead::CHACHA20_POLY1305.tag_len())
            .and_then(|length| u32::try_from(length).ok())
            .ok_or_else(|| {
                SpoolError::new(
                    "DBX-RS-SPOOL-LIMIT-0007",
                    "frame_encode",
                    "spool frame is too large",
                )
            })?;
        let sequence = self.next_sequence;
        let aad = frame_aad(&self.prefix, cipher_length, sequence);
        self.key
            .seal_in_place_append_tag(nonce(sequence), Aad::from(aad.as_slice()), &mut plaintext)
            .map_err(|_| {
                SpoolError::new(
                    "DBX-RS-SPOOL-CRYPTO-0001",
                    "frame_encrypt",
                    "spool frame encryption failed",
                )
            })?;
        self.file
            .write_all(&cipher_length.to_be_bytes())
            .and_then(|()| self.file.write_all(&sequence.to_be_bytes()))
            .and_then(|()| self.file.write_all(&plaintext))
            .map_err(|error| {
                SpoolError::io(
                    "DBX-RS-SPOOL-FORMAT-0005",
                    if payload_is_event {
                        "event_write"
                    } else {
                        "metadata_write"
                    },
                    "failed to write an encrypted spool frame",
                    &error,
                )
            })?;
        let frame_bytes = FRAME_PREFIX_BYTES
            .checked_add(u64::from(cipher_length))
            .ok_or_else(|| {
                SpoolError::new(
                    "DBX-RS-SPOOL-LIMIT-0008",
                    "frame_encode",
                    "spool frame length overflowed",
                )
            })?;
        self.position = self.position.checked_add(frame_bytes).ok_or_else(|| {
            SpoolError::new(
                "DBX-RS-SPOOL-LIMIT-0008",
                "frame_encode",
                "spool frame length overflowed",
            )
        })?;
        self.next_sequence = self.next_sequence.checked_add(1).ok_or_else(|| {
            SpoolError::new(
                "DBX-RS-SPOOL-LIMIT-0009",
                "frame_encode",
                "spool frame sequence overflowed",
            )
        })?;
        Ok(())
    }
}

pub(crate) struct SegmentDecoder {
    reader: BufReader<File>,
    key: LessSafeKey,
    prefix: [u8; PREFIX_BYTES],
    segment_id: SegmentId,
    next_sequence: u64,
    event_count: u64,
    plaintext_bytes: u64,
    digest: Context,
    summary: Option<SegmentSummary>,
    done: bool,
    limit: u64,
    remaining_bytes: u64,
    pub(crate) header: SegmentHeader,
}

impl SegmentDecoder {
    pub(crate) fn open(file: File, spool_key: &SpoolKey, limit: u64) -> Result<Self, SpoolError> {
        let metadata = file.metadata().map_err(|error| {
            SpoolError::io(
                "DBX-RS-SPOOL-FORMAT-0006",
                "segment_read",
                "failed to inspect a spool segment",
                &error,
            )
        })?;
        if !metadata.is_file() || metadata.len() > limit {
            return Err(SpoolError::new(
                "DBX-RS-SPOOL-FORMAT-0007",
                "segment_read",
                "spool segment type or size is invalid",
            ));
        }
        let remaining_bytes = metadata
            .len()
            .checked_sub(PREFIX_BYTES as u64)
            .ok_or_else(truncated_segment)?;
        let mut reader = BufReader::new(file);
        let mut prefix = [0_u8; PREFIX_BYTES];
        read_exact(&mut reader, &mut prefix, "prefix_read")?;
        let (key_id, salt, segment_id) = decode_prefix(&prefix)?;
        if key_id != spool_key.id {
            return Err(SpoolError::new(
                "DBX-RS-SPOOL-CRYPTO-0002",
                "key_match",
                "spool segment belongs to a different key",
            ));
        }
        let key = derive_segment_key(&spool_key.bytes, &salt, segment_id)?;
        let mut decoder = Self {
            reader,
            key,
            prefix,
            segment_id,
            next_sequence: 0,
            event_count: 0,
            plaintext_bytes: 0,
            digest: Context::new(&SHA256),
            summary: None,
            done: false,
            limit,
            remaining_bytes,
            header: SegmentHeader {
                input_key: InputKey::new([0; 32]),
                configuration_fingerprint: Fingerprint::new([0; 32]),
                configuration_generation: 0,
                batch_id: BatchId::new([0; 16]),
                batch_sequence: 0,
                segment_sequence: 0,
                created_epoch_millis: 0,
            },
        };
        let header_frame = decoder.read_frame()?;
        if header_frame.first().copied() != Some(FRAME_HEADER) {
            return Err(invalid_frame_type());
        }
        decoder.header = decode_header(&header_frame[1..])?;
        Ok(decoder)
    }

    pub(crate) const fn segment_id(&self) -> SegmentId {
        self.segment_id
    }

    pub(crate) const fn summary(&self) -> Option<SegmentSummary> {
        self.summary
    }

    pub(crate) fn next_event(&mut self) -> Result<Option<Vec<u8>>, SpoolError> {
        if self.done {
            return Ok(None);
        }
        let frame = self.read_frame()?;
        let (&frame_type, payload) = frame.split_first().ok_or_else(invalid_frame_type)?;
        match frame_type {
            FRAME_EVENT => {
                if payload.is_empty() {
                    return Err(SpoolError::new(
                        "DBX-RS-SPOOL-FORMAT-0008",
                        "event_read",
                        "spool event frame is empty",
                    ));
                }
                let event_bytes = u64::try_from(payload.len()).map_err(|_| {
                    SpoolError::new(
                        "DBX-RS-SPOOL-LIMIT-0010",
                        "event_read",
                        "spool plaintext byte count overflowed",
                    )
                })?;
                self.event_count = self.event_count.checked_add(1).ok_or_else(|| {
                    SpoolError::new(
                        "DBX-RS-SPOOL-LIMIT-0011",
                        "event_read",
                        "spool event count overflowed",
                    )
                })?;
                self.plaintext_bytes =
                    self.plaintext_bytes
                        .checked_add(event_bytes)
                        .ok_or_else(|| {
                            SpoolError::new(
                                "DBX-RS-SPOOL-LIMIT-0010",
                                "event_read",
                                "spool plaintext byte count overflowed",
                            )
                        })?;
                self.digest.update(&event_bytes.to_be_bytes());
                self.digest.update(payload);
                Ok(Some(payload.to_vec()))
            }
            FRAME_FOOTER => {
                let summary = decode_footer(payload)?;
                let digest = self.digest.clone().finish();
                if summary.event_count != self.event_count
                    || summary.plaintext_bytes != self.plaintext_bytes
                    || summary.stream_digest.as_slice() != digest.as_ref()
                {
                    return Err(SpoolError::new(
                        "DBX-RS-SPOOL-FORMAT-0009",
                        "footer_validate",
                        "spool footer accounting or digest is invalid",
                    ));
                }
                let mut trailing = [0_u8; 1];
                let trailing_bytes = self.reader.read(&mut trailing).map_err(|error| {
                    SpoolError::io(
                        "DBX-RS-SPOOL-FORMAT-0010",
                        "trailing_validate",
                        "failed to inspect the spool segment terminator",
                        &error,
                    )
                })?;
                if trailing_bytes != 0 {
                    return Err(SpoolError::new(
                        "DBX-RS-SPOOL-FORMAT-0011",
                        "trailing_validate",
                        "spool segment has trailing data",
                    ));
                }
                self.summary = Some(summary);
                self.done = true;
                Ok(None)
            }
            FRAME_HEADER => Err(SpoolError::new(
                "DBX-RS-SPOOL-FORMAT-0012",
                "frame_order",
                "spool segment contains a repeated header",
            )),
            _ => Err(invalid_frame_type()),
        }
    }

    fn read_frame(&mut self) -> Result<Vec<u8>, SpoolError> {
        if self.remaining_bytes < FRAME_PREFIX_BYTES {
            return Err(truncated_segment());
        }
        let mut length_bytes = [0_u8; 4];
        read_exact(&mut self.reader, &mut length_bytes, "frame_read")?;
        let cipher_length = u32::from_be_bytes(length_bytes);
        let minimum_cipher = 1_u32
            .saturating_add(u32::try_from(aead::CHACHA20_POLY1305.tag_len()).unwrap_or(u32::MAX));
        if cipher_length < minimum_cipher || u64::from(cipher_length) > self.limit {
            return Err(SpoolError::new(
                "DBX-RS-SPOOL-FORMAT-0013",
                "frame_read",
                "encrypted spool frame length is invalid",
            ));
        }
        let mut sequence_bytes = [0_u8; 8];
        read_exact(&mut self.reader, &mut sequence_bytes, "frame_read")?;
        let sequence = u64::from_be_bytes(sequence_bytes);
        if sequence != self.next_sequence {
            return Err(SpoolError::new(
                "DBX-RS-SPOOL-FORMAT-0014",
                "frame_sequence",
                "spool frame sequence is invalid",
            ));
        }
        let remaining_ciphertext = self.remaining_bytes - FRAME_PREFIX_BYTES;
        if u64::from(cipher_length) > remaining_ciphertext {
            return Err(truncated_segment());
        }
        if u64::from(cipher_length) > maximum_ciphertext_frame_bytes(self.limit) {
            return Err(SpoolError::new(
                "DBX-RS-SPOOL-FORMAT-0013",
                "frame_read",
                "encrypted spool frame length is invalid",
            ));
        }
        let allocation = usize::try_from(cipher_length).map_err(|_| {
            SpoolError::new(
                "DBX-RS-SPOOL-LIMIT-0012",
                "frame_read",
                "spool frame cannot fit this platform",
            )
        })?;
        let mut ciphertext = vec![0_u8; allocation];
        read_exact(&mut self.reader, &mut ciphertext, "frame_read")?;
        self.remaining_bytes = remaining_ciphertext - u64::from(cipher_length);
        let aad = frame_aad(&self.prefix, cipher_length, sequence);
        let plaintext_length = self
            .key
            .open_in_place(nonce(sequence), Aad::from(aad.as_slice()), &mut ciphertext)
            .map_err(|_| {
                SpoolError::new(
                    "DBX-RS-SPOOL-CRYPTO-0003",
                    "frame_authenticate",
                    "spool frame authentication failed",
                )
            })?
            .len();
        ciphertext.truncate(plaintext_length);
        self.next_sequence = self.next_sequence.checked_add(1).ok_or_else(|| {
            SpoolError::new(
                "DBX-RS-SPOOL-LIMIT-0013",
                "frame_sequence",
                "spool frame sequence overflowed",
            )
        })?;
        Ok(ciphertext)
    }
}

fn encode_prefix(
    key_id: [u8; KEY_ID_BYTES],
    salt: [u8; SALT_BYTES],
    segment_id: SegmentId,
) -> [u8; PREFIX_BYTES] {
    let mut prefix = [0_u8; PREFIX_BYTES];
    let mut offset = 0;
    put(&mut prefix, &mut offset, MAGIC);
    put(&mut prefix, &mut offset, &FORMAT_VERSION.to_be_bytes());
    put(&mut prefix, &mut offset, &key_id);
    put(&mut prefix, &mut offset, &salt);
    put(&mut prefix, &mut offset, segment_id.as_bytes());
    prefix
}

fn decode_prefix(
    prefix: &[u8; PREFIX_BYTES],
) -> Result<([u8; KEY_ID_BYTES], [u8; SALT_BYTES], SegmentId), SpoolError> {
    if &prefix[..MAGIC.len()] != MAGIC {
        return Err(SpoolError::new(
            "DBX-RS-SPOOL-FORMAT-0015",
            "prefix_validate",
            "spool segment magic is invalid",
        ));
    }
    let version_offset = MAGIC.len();
    let version = u16::from_be_bytes([prefix[version_offset], prefix[version_offset + 1]]);
    if version != FORMAT_VERSION {
        return Err(SpoolError::new(
            "DBX-RS-SPOOL-FORMAT-0016",
            "version_validate",
            "spool segment format version is unsupported",
        ));
    }
    let mut offset = MAGIC.len() + 2;
    let key_id = take::<KEY_ID_BYTES>(prefix, &mut offset);
    let salt = take::<SALT_BYTES>(prefix, &mut offset);
    let segment_id = SegmentId::new(take::<16>(prefix, &mut offset));
    Ok((key_id, salt, segment_id))
}

fn encode_header(header: SegmentHeader) -> [u8; HEADER_PAYLOAD_BYTES] {
    let mut encoded = [0_u8; HEADER_PAYLOAD_BYTES];
    let mut offset = 0;
    put(&mut encoded, &mut offset, header.input_key.as_bytes());
    put(
        &mut encoded,
        &mut offset,
        header.configuration_fingerprint.as_bytes(),
    );
    put(
        &mut encoded,
        &mut offset,
        &header.configuration_generation.to_be_bytes(),
    );
    put(&mut encoded, &mut offset, header.batch_id.as_bytes());
    put(
        &mut encoded,
        &mut offset,
        &header.batch_sequence.to_be_bytes(),
    );
    put(
        &mut encoded,
        &mut offset,
        &header.segment_sequence.to_be_bytes(),
    );
    put(
        &mut encoded,
        &mut offset,
        &header.created_epoch_millis.to_be_bytes(),
    );
    encoded
}

fn decode_header(payload: &[u8]) -> Result<SegmentHeader, SpoolError> {
    if payload.len() != HEADER_PAYLOAD_BYTES {
        return Err(SpoolError::new(
            "DBX-RS-SPOOL-FORMAT-0017",
            "header_decode",
            "encrypted spool header length is invalid",
        ));
    }
    let mut offset = 0;
    Ok(SegmentHeader {
        input_key: InputKey::new(take::<32>(payload, &mut offset)),
        configuration_fingerprint: Fingerprint::new(take::<32>(payload, &mut offset)),
        configuration_generation: u64::from_be_bytes(take::<8>(payload, &mut offset)),
        batch_id: BatchId::new(take::<16>(payload, &mut offset)),
        batch_sequence: u64::from_be_bytes(take::<8>(payload, &mut offset)),
        segment_sequence: u64::from_be_bytes(take::<8>(payload, &mut offset)),
        created_epoch_millis: u64::from_be_bytes(take::<8>(payload, &mut offset)),
    })
}

fn encode_footer(summary: SegmentSummary) -> [u8; FOOTER_PAYLOAD_BYTES] {
    let mut encoded = [0_u8; FOOTER_PAYLOAD_BYTES];
    let mut offset = 0;
    put(
        &mut encoded,
        &mut offset,
        &summary.event_count.to_be_bytes(),
    );
    put(
        &mut encoded,
        &mut offset,
        &summary.plaintext_bytes.to_be_bytes(),
    );
    put(&mut encoded, &mut offset, &summary.stream_digest);
    encoded
}

fn decode_footer(payload: &[u8]) -> Result<SegmentSummary, SpoolError> {
    if payload.len() != FOOTER_PAYLOAD_BYTES {
        return Err(SpoolError::new(
            "DBX-RS-SPOOL-FORMAT-0018",
            "footer_decode",
            "encrypted spool footer length is invalid",
        ));
    }
    let mut offset = 0;
    Ok(SegmentSummary {
        event_count: u64::from_be_bytes(take::<8>(payload, &mut offset)),
        plaintext_bytes: u64::from_be_bytes(take::<8>(payload, &mut offset)),
        stream_digest: take::<32>(payload, &mut offset),
    })
}

fn encoded_frame_bytes(plaintext_length: usize) -> Result<u64, SpoolError> {
    let cipher_length = plaintext_length
        .checked_add(aead::CHACHA20_POLY1305.tag_len())
        .ok_or_else(|| {
            SpoolError::new(
                "DBX-RS-SPOOL-LIMIT-0014",
                "frame_size",
                "spool frame length overflowed",
            )
        })?;
    let cipher_length = u64::try_from(cipher_length).map_err(|_| {
        SpoolError::new(
            "DBX-RS-SPOOL-LIMIT-0014",
            "frame_size",
            "spool frame length overflowed",
        )
    })?;
    FRAME_PREFIX_BYTES
        .checked_add(cipher_length)
        .ok_or_else(|| {
            SpoolError::new(
                "DBX-RS-SPOOL-LIMIT-0014",
                "frame_size",
                "spool frame length overflowed",
            )
        })
}

fn minimum_footer_frame_bytes() -> u64 {
    encoded_frame_bytes(FOOTER_PAYLOAD_BYTES + 1).unwrap_or(u64::MAX)
}

pub(crate) fn maximum_ciphertext_frame_bytes(limit: u64) -> u64 {
    let fixed_format_bytes = (PREFIX_BYTES as u64)
        .checked_add(encoded_frame_bytes(HEADER_PAYLOAD_BYTES + 1).unwrap_or(u64::MAX))
        .and_then(|bytes| bytes.checked_add(minimum_footer_frame_bytes()))
        .and_then(|bytes| bytes.checked_add(FRAME_PREFIX_BYTES));
    fixed_format_bytes.map_or(0, |bytes| limit.saturating_sub(bytes))
}

fn derive_segment_key(
    master_key: &[u8; KEY_BYTES],
    salt: &[u8; SALT_BYTES],
    segment_id: SegmentId,
) -> Result<LessSafeKey, SpoolError> {
    struct KeyLength;
    impl hkdf::KeyType for KeyLength {
        fn len(&self) -> usize {
            KEY_BYTES
        }
    }

    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, salt);
    let prk = salt.extract(master_key);
    let info = [b"dbx-rs-spool-segment-v1".as_slice(), segment_id.as_bytes()];
    let okm = prk.expand(&info, KeyLength).map_err(|_| {
        SpoolError::new(
            "DBX-RS-SPOOL-CRYPTO-0004",
            "key_derive",
            "spool segment key derivation failed",
        )
    })?;
    let mut derived = [0_u8; KEY_BYTES];
    okm.fill(&mut derived).map_err(|_| {
        SpoolError::new(
            "DBX-RS-SPOOL-CRYPTO-0004",
            "key_derive",
            "spool segment key derivation failed",
        )
    })?;
    let key = UnboundKey::new(&aead::CHACHA20_POLY1305, &derived)
        .map(LessSafeKey::new)
        .map_err(|_| {
            SpoolError::new(
                "DBX-RS-SPOOL-CRYPTO-0005",
                "key_initialize",
                "spool segment key initialization failed",
            )
        });
    derived.fill(0);
    key
}

fn frame_aad(prefix: &[u8; PREFIX_BYTES], cipher_length: u32, sequence: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(PREFIX_BYTES + 4 + 8);
    aad.extend_from_slice(prefix);
    aad.extend_from_slice(&cipher_length.to_be_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad
}

fn nonce(sequence: u64) -> Nonce {
    let mut bytes = [0_u8; aead::NONCE_LEN];
    bytes[4..].copy_from_slice(&sequence.to_be_bytes());
    Nonce::assume_unique_for_key(bytes)
}

fn read_exact(
    reader: &mut impl Read,
    output: &mut [u8],
    stage: &'static str,
) -> Result<(), SpoolError> {
    reader.read_exact(output).map_err(|error| {
        if error.kind() == std::io::ErrorKind::UnexpectedEof {
            SpoolError::new(
                "DBX-RS-SPOOL-FORMAT-0019",
                stage,
                "spool segment is truncated",
            )
        } else {
            SpoolError::io(
                "DBX-RS-SPOOL-FORMAT-0020",
                stage,
                "failed to read a spool segment",
                &error,
            )
        }
    })
}

const fn truncated_segment() -> SpoolError {
    SpoolError::new(
        "DBX-RS-SPOOL-FORMAT-0019",
        "frame_read",
        "spool segment is truncated",
    )
}

fn put(output: &mut [u8], offset: &mut usize, value: &[u8]) {
    let end = *offset + value.len();
    output[*offset..end].copy_from_slice(value);
    *offset = end;
}

fn take<const N: usize>(input: &[u8], offset: &mut usize) -> [u8; N] {
    let end = *offset + N;
    let mut output = [0_u8; N];
    output.copy_from_slice(&input[*offset..end]);
    *offset = end;
    output
}

const fn invalid_frame_type() -> SpoolError {
    SpoolError::new(
        "DBX-RS-SPOOL-FORMAT-0021",
        "frame_type",
        "spool frame type is invalid",
    )
}
