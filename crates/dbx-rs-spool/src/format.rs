use std::fs::File;
use std::io::{BufReader, Read, Write};

use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::digest::{Context, SHA256};
use ring::hkdf;

use crate::error::SpoolError;
use crate::identity::{BatchId, Fingerprint, InputKey, SegmentId};
use crate::key::{KEY_BYTES, KEY_ID_BYTES, SpoolKey};
use crate::model::{MAX_RECOVERY_METADATA_BYTES, RecoveryMetadata, SegmentHeader, SegmentSummary};

pub(crate) const MAGIC: &[u8; 8] = b"DBXRSSPL";
pub(crate) const LEGACY_FORMAT_VERSION: u16 = 1;
pub(crate) const FORMAT_VERSION: u16 = 2;
const SALT_BYTES: usize = 32;
pub(crate) const PREFIX_BYTES: usize = MAGIC.len() + 2 + KEY_ID_BYTES + SALT_BYTES + 16;
const FRAME_PREFIX_BYTES: u64 = 4 + 8;
const HEADER_PAYLOAD_BYTES: usize = 32 + 32 + 8 + 16 + 8 + 8 + 8;
const FOOTER_PAYLOAD_BYTES: usize = 8 + 8 + 32;
const FRAME_HEADER: u8 = 1;
const FRAME_EVENT: u8 = 2;
const FRAME_FOOTER: u8 = 3;
const FRAME_RECOVERY_METADATA: u8 = 4;

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
    format_version: u16,
}

impl SegmentEncoder {
    pub(crate) fn start(
        file: File,
        spool_key: &SpoolKey,
        salt: [u8; SALT_BYTES],
        segment_id: SegmentId,
        header: SegmentHeader,
        limit: u64,
    ) -> Result<Self, SpoolError> {
        Self::start_with_version(
            file,
            spool_key,
            salt,
            segment_id,
            header,
            limit,
            FORMAT_VERSION,
        )
    }

    fn start_with_version(
        mut file: File,
        spool_key: &SpoolKey,
        salt: [u8; SALT_BYTES],
        segment_id: SegmentId,
        header: SegmentHeader,
        limit: u64,
        format_version: u16,
    ) -> Result<Self, SpoolError> {
        let prefix = encode_prefix(spool_key.id, salt, segment_id, format_version);
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
            format_version,
        };
        let header_payload = encode_header(header);
        encoder.write_typed_frame(FRAME_HEADER, &header_payload, false)?;
        if encoder
            .position
            .checked_add(terminal_frame_bytes(format_version))
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
            .and_then(|position| position.checked_add(terminal_frame_bytes(self.format_version)))
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

    pub(crate) fn finish(
        self,
        recovery_metadata: &RecoveryMetadata,
    ) -> Result<(File, SegmentSummary, u64), SpoolError> {
        self.finish_inner(Some(recovery_metadata))
    }

    fn finish_inner(
        mut self,
        recovery_metadata: Option<&RecoveryMetadata>,
    ) -> Result<(File, SegmentSummary, u64), SpoolError> {
        let digest = self.digest.clone().finish();
        let mut stream_digest = [0_u8; 32];
        stream_digest.copy_from_slice(digest.as_ref());
        let summary = SegmentSummary {
            event_count: self.event_count,
            plaintext_bytes: self.plaintext_bytes,
            stream_digest,
        };
        match (self.format_version, recovery_metadata) {
            (FORMAT_VERSION, Some(recovery_metadata)) => {
                self.write_typed_frame(
                    FRAME_RECOVERY_METADATA,
                    recovery_metadata.as_bytes(),
                    false,
                )?;
            }
            (LEGACY_FORMAT_VERSION, None) => {}
            _ => return Err(invalid_version()),
        }
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

    #[cfg(test)]
    fn finish_legacy(self) -> Result<(File, SegmentSummary, u64), SpoolError> {
        self.finish_inner(None)
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
    format_version: u16,
    recovery_metadata: Option<RecoveryMetadata>,
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
        let (format_version, key_id, salt, segment_id) = decode_prefix(&prefix)?;
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
            format_version,
            recovery_metadata: None,
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

    pub(crate) const fn format_version(&self) -> u16 {
        self.format_version
    }

    pub(crate) const fn summary(&self) -> Option<SegmentSummary> {
        self.summary
    }

    pub(crate) fn recovery_metadata(&self) -> Option<&RecoveryMetadata> {
        self.recovery_metadata.as_ref()
    }

    pub(crate) fn next_event(&mut self) -> Result<Option<Vec<u8>>, SpoolError> {
        if self.done {
            return Ok(None);
        }
        loop {
            let frame = self.read_frame()?;
            let (&frame_type, payload) = frame.split_first().ok_or_else(invalid_frame_type)?;
            match frame_type {
                FRAME_EVENT => return self.accept_event(payload).map(Some),
                FRAME_RECOVERY_METADATA => {
                    if self.format_version != FORMAT_VERSION {
                        return Err(invalid_frame_type());
                    }
                    if self.recovery_metadata.is_some() {
                        return Err(repeated_metadata_error());
                    }
                    self.recovery_metadata = Some(RecoveryMetadata::new(payload)?);
                }
                FRAME_FOOTER => {
                    self.accept_footer(payload)?;
                    return Ok(None);
                }
                FRAME_HEADER => {
                    return Err(SpoolError::new(
                        "DBX-RS-SPOOL-FORMAT-0012",
                        "frame_order",
                        "spool segment contains a repeated header",
                    ));
                }
                _ => return Err(invalid_frame_type()),
            }
        }
    }

    fn accept_event(&mut self, payload: &[u8]) -> Result<Vec<u8>, SpoolError> {
        if self.format_version == FORMAT_VERSION && self.recovery_metadata.is_some() {
            return Err(metadata_order_error());
        }
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
        self.plaintext_bytes = self
            .plaintext_bytes
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
        Ok(payload.to_vec())
    }

    fn accept_footer(&mut self, payload: &[u8]) -> Result<(), SpoolError> {
        if self.format_version == FORMAT_VERSION && self.recovery_metadata.is_none() {
            return Err(missing_metadata_error());
        }
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
        if self.format_version == LEGACY_FORMAT_VERSION {
            self.recovery_metadata = Some(RecoveryMetadata::empty());
        }
        self.summary = Some(summary);
        self.done = true;
        Ok(())
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
        if u64::from(cipher_length)
            > maximum_ciphertext_frame_bytes(self.limit, self.format_version)
        {
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
    format_version: u16,
) -> [u8; PREFIX_BYTES] {
    let mut prefix = [0_u8; PREFIX_BYTES];
    let mut offset = 0;
    put(&mut prefix, &mut offset, MAGIC);
    put(&mut prefix, &mut offset, &format_version.to_be_bytes());
    put(&mut prefix, &mut offset, &key_id);
    put(&mut prefix, &mut offset, &salt);
    put(&mut prefix, &mut offset, segment_id.as_bytes());
    prefix
}

fn decode_prefix(
    prefix: &[u8; PREFIX_BYTES],
) -> Result<(u16, [u8; KEY_ID_BYTES], [u8; SALT_BYTES], SegmentId), SpoolError> {
    if &prefix[..MAGIC.len()] != MAGIC {
        return Err(SpoolError::new(
            "DBX-RS-SPOOL-FORMAT-0015",
            "prefix_validate",
            "spool segment magic is invalid",
        ));
    }
    let version_offset = MAGIC.len();
    let version = u16::from_be_bytes([prefix[version_offset], prefix[version_offset + 1]]);
    if !matches!(version, LEGACY_FORMAT_VERSION | FORMAT_VERSION) {
        return Err(invalid_version());
    }
    let mut offset = MAGIC.len() + 2;
    let key_id = take::<KEY_ID_BYTES>(prefix, &mut offset);
    let salt = take::<SALT_BYTES>(prefix, &mut offset);
    let segment_id = SegmentId::new(take::<16>(prefix, &mut offset));
    Ok((version, key_id, salt, segment_id))
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

fn footer_frame_bytes() -> u64 {
    encoded_frame_bytes(FOOTER_PAYLOAD_BYTES + 1).unwrap_or(u64::MAX)
}

fn maximum_recovery_metadata_frame_bytes() -> u64 {
    encoded_frame_bytes(MAX_RECOVERY_METADATA_BYTES + 1).unwrap_or(u64::MAX)
}

fn terminal_frame_bytes(format_version: u16) -> u64 {
    match format_version {
        LEGACY_FORMAT_VERSION => footer_frame_bytes(),
        FORMAT_VERSION => {
            maximum_recovery_metadata_frame_bytes().saturating_add(footer_frame_bytes())
        }
        _ => u64::MAX,
    }
}

pub(crate) fn maximum_ciphertext_frame_bytes(limit: u64, format_version: u16) -> u64 {
    let header_frame_bytes = encoded_frame_bytes(HEADER_PAYLOAD_BYTES + 1).unwrap_or(u64::MAX);
    let fixed_format_bytes = (PREFIX_BYTES as u64)
        .checked_add(header_frame_bytes)
        .and_then(|bytes| bytes.checked_add(terminal_frame_bytes(format_version)))
        .and_then(|bytes| bytes.checked_add(FRAME_PREFIX_BYTES));
    let maximum_event_ciphertext =
        fixed_format_bytes.map_or(0, |bytes| limit.saturating_sub(bytes));
    match format_version {
        LEGACY_FORMAT_VERSION => maximum_event_ciphertext,
        FORMAT_VERSION => maximum_event_ciphertext
            .max((HEADER_PAYLOAD_BYTES + 1 + aead::CHACHA20_POLY1305.tag_len()) as u64)
            .max((MAX_RECOVERY_METADATA_BYTES + 1 + aead::CHACHA20_POLY1305.tag_len()) as u64)
            .max((FOOTER_PAYLOAD_BYTES + 1 + aead::CHACHA20_POLY1305.tag_len()) as u64),
        _ => 0,
    }
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

const fn invalid_version() -> SpoolError {
    SpoolError::new(
        "DBX-RS-SPOOL-FORMAT-0016",
        "version_validate",
        "spool segment format version is unsupported",
    )
}

const fn missing_metadata_error() -> SpoolError {
    SpoolError::new(
        "DBX-RS-SPOOL-FORMAT-0025",
        "recovery_metadata",
        "version 2 spool segment has no recovery metadata frame",
    )
}

const fn repeated_metadata_error() -> SpoolError {
    SpoolError::new(
        "DBX-RS-SPOOL-FORMAT-0026",
        "recovery_metadata",
        "spool segment contains repeated recovery metadata",
    )
}

const fn metadata_order_error() -> SpoolError {
    SpoolError::new(
        "DBX-RS-SPOOL-FORMAT-0027",
        "frame_order",
        "spool recovery metadata is not the final frame before the footer",
    )
}

#[cfg(test)]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct Fixture {
        root: PathBuf,
        segment_path: PathBuf,
        key: SpoolKey,
    }

    impl Fixture {
        fn new(label: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "dbx-rs-format-{label}-{}-{}",
                std::process::id(),
                NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&root).expect("test directory must be created");
            let key = SpoolKey::load_or_create(&root.join("keys/spool.key"))
                .expect("test key must be created");
            Self {
                segment_path: root.join("segment.dbx"),
                root,
                key,
            }
        }

        fn encoder(&self, format_version: u16) -> SegmentEncoder {
            let file = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&self.segment_path)
                .expect("segment file must be created");
            SegmentEncoder::start_with_version(
                file,
                &self.key,
                [0x21; SALT_BYTES],
                SegmentId::new([0x31; 16]),
                header(),
                4_096,
                format_version,
            )
            .expect("encoder must start")
        }

        fn decoder(&self) -> Result<SegmentDecoder, SpoolError> {
            let file = File::open(&self.segment_path).expect("segment must open");
            SegmentDecoder::open(file, &self.key, 4_096)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ignored = fs::remove_dir_all(&self.root);
        }
    }

    fn header() -> SegmentHeader {
        SegmentHeader {
            input_key: InputKey::new([0x41; 32]),
            configuration_fingerprint: Fingerprint::new([0x42; 32]),
            configuration_generation: 3,
            batch_id: BatchId::new([0x43; 16]),
            batch_sequence: 5,
            segment_sequence: 7,
            created_epoch_millis: 11,
        }
    }

    fn summary(encoder: &SegmentEncoder) -> SegmentSummary {
        let digest = encoder.digest.clone().finish();
        let mut stream_digest = [0_u8; 32];
        stream_digest.copy_from_slice(digest.as_ref());
        SegmentSummary {
            event_count: encoder.event_count,
            plaintext_bytes: encoder.plaintext_bytes,
            stream_digest,
        }
    }

    fn write_footer(mut encoder: SegmentEncoder) {
        let footer = encode_footer(summary(&encoder));
        encoder
            .write_typed_frame(FRAME_FOOTER, &footer, false)
            .expect("footer must write");
        encoder.file.sync_all().expect("segment must synchronize");
    }

    fn decode_to_end(fixture: &Fixture) -> Result<SegmentDecoder, SpoolError> {
        let mut decoder = fixture.decoder()?;
        while decoder.next_event()?.is_some() {}
        Ok(decoder)
    }

    fn decode_error(fixture: &Fixture, message: &str) -> SpoolError {
        match decode_to_end(fixture) {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }

    #[test]
    fn version_one_segment_remains_readable_with_empty_recovery_metadata() {
        let fixture = Fixture::new("v1");
        let mut encoder = fixture.encoder(LEGACY_FORMAT_VERSION);
        encoder.append_event(b"legacy").expect("event must append");
        let _sealed = encoder.finish_legacy().expect("legacy segment must finish");

        let mut decoder = fixture.decoder().expect("legacy decoder must open");
        assert_eq!(decoder.format_version(), LEGACY_FORMAT_VERSION);
        assert_eq!(
            decoder.next_event().expect("event must decode"),
            Some(b"legacy".to_vec())
        );
        assert_eq!(decoder.next_event().expect("footer must decode"), None);
        assert_eq!(
            decoder
                .recovery_metadata()
                .expect("legacy metadata view must exist")
                .as_bytes(),
            b""
        );
    }

    #[test]
    fn version_two_rejects_missing_repeated_and_out_of_order_metadata() {
        let missing = Fixture::new("missing-metadata");
        let mut encoder = missing.encoder(FORMAT_VERSION);
        encoder.append_event(b"event").expect("event must append");
        write_footer(encoder);
        assert_eq!(
            decode_error(&missing, "missing metadata must fail").code(),
            "DBX-RS-SPOOL-FORMAT-0025"
        );

        let repeated = Fixture::new("repeated-metadata");
        let mut encoder = repeated.encoder(FORMAT_VERSION);
        encoder.append_event(b"event").expect("event must append");
        encoder
            .write_typed_frame(FRAME_RECOVERY_METADATA, b"first", false)
            .expect("metadata must write");
        encoder
            .write_typed_frame(FRAME_RECOVERY_METADATA, b"second", false)
            .expect("metadata must write");
        write_footer(encoder);
        assert_eq!(
            decode_error(&repeated, "repeated metadata must fail").code(),
            "DBX-RS-SPOOL-FORMAT-0026"
        );

        let out_of_order = Fixture::new("out-of-order-metadata");
        let mut encoder = out_of_order.encoder(FORMAT_VERSION);
        encoder
            .write_typed_frame(FRAME_RECOVERY_METADATA, b"metadata", false)
            .expect("metadata must write");
        encoder.append_event(b"event").expect("event must append");
        write_footer(encoder);
        assert_eq!(
            decode_error(&out_of_order, "event after metadata must fail").code(),
            "DBX-RS-SPOOL-FORMAT-0027"
        );
    }

    #[test]
    fn decoder_rejects_authenticated_oversize_recovery_metadata() {
        let fixture = Fixture::new("oversize-metadata");
        let mut encoder = fixture.encoder(FORMAT_VERSION);
        encoder
            .write_typed_frame(
                FRAME_RECOVERY_METADATA,
                &[0x51; MAX_RECOVERY_METADATA_BYTES + 1],
                false,
            )
            .expect("raw oversize metadata must write for the decoder test");
        write_footer(encoder);

        assert_eq!(
            decode_error(&fixture, "oversize metadata must fail").code(),
            "DBX-RS-SPOOL-LIMIT-0015"
        );
    }
}
