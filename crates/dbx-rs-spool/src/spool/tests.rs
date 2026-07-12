use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier, mpsc};

use super::*;
use crate::{BatchId, Fingerprint, MAX_RECOVERY_METADATA_BYTES, RecoveryMetadata, SegmentId};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    root: PathBuf,
    key_path: PathBuf,
    spool_path: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "dbx-rs-spool-{}-{}",
            std::process::id(),
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        Self {
            key_path: root.join("keys/spool.key"),
            spool_path: root.join("spool"),
            root,
        }
    }

    fn open(&self, limits: SpoolLimits) -> Spool {
        let key = SpoolKey::load_or_create(&self.key_path).expect("spool key must open");
        Spool::open(&self.spool_path, key, limits).expect("spool must open")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ignored = fs::remove_dir_all(&self.root);
    }
}

fn limits() -> SpoolLimits {
    SpoolLimits::new(16 * 1024, 64 * 1024, 256 * 1024).expect("limits are valid")
}

fn input(byte: u8) -> InputKey {
    InputKey::new([byte; 32])
}

fn header(input_key: InputKey, batch_sequence: u64, segment_sequence: u64) -> SegmentHeader {
    SegmentHeader {
        input_key,
        configuration_fingerprint: Fingerprint::new([0x31; 32]),
        configuration_generation: 7,
        batch_id: BatchId::new([u8::try_from(batch_sequence).unwrap_or(0); 16]),
        batch_sequence,
        segment_sequence,
        created_epoch_millis: 1_720_000_000_123,
    }
}

fn seal(spool: &Spool, header: SegmentHeader, events: &[&[u8]]) -> ReadySegment {
    let mut writer = spool.begin_segment(header).expect("segment must begin");
    for event in events {
        writer.append_event(event).expect("event must append");
    }
    writer.seal().expect("segment must seal")
}

fn read_events(spool: &Spool, segment: &ReadySegment) -> Vec<Vec<u8>> {
    spool
        .reader(segment)
        .expect("reader must open")
        .collect::<Result<Vec<_>, _>>()
        .expect("segment must validate")
}

fn mutate(path: &Path, offset: u64, replacement: u8) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("segment must open for corruption test");
    file.seek(SeekFrom::Start(offset))
        .expect("corruption offset must seek");
    file.write_all(&[replacement])
        .expect("corruption byte must write");
    file.sync_all().expect("corruption must synchronize");
}

fn overwrite(path: &Path, offset: u64, replacement: &[u8]) {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .expect("segment must open for corruption test");
    file.seek(SeekFrom::Start(offset))
        .expect("corruption offset must seek");
    file.write_all(replacement)
        .expect("corruption bytes must write");
    file.sync_all().expect("corruption must synchronize");
}

fn encrypted_frame_payload_offsets(path: &Path) -> Vec<u64> {
    let bytes = fs::read(path).expect("segment must be readable");
    let mut offset = crate::format::PREFIX_BYTES;
    let mut payloads = Vec::new();
    while offset < bytes.len() {
        let length = u32::from_be_bytes(
            bytes[offset..offset + 4]
                .try_into()
                .expect("frame length must exist"),
        ) as usize;
        payloads.push(u64::try_from(offset + 12).expect("frame offset must fit"));
        offset += 12 + length;
    }
    assert_eq!(offset, bytes.len());
    payloads
}

#[test]
fn encrypted_segment_round_trips_multiple_exact_events() {
    let fixture = Fixture::new();
    let spool = fixture.open(limits());
    let events = [
        br#"{"event":{"id":1}}"#.as_slice(),
        br#"{"event":{"id":2,"value":"two"}}"#.as_slice(),
        br#"{"event":{"id":3,"null":null}}"#.as_slice(),
    ];
    let ready = seal(&spool, header(input(1), 4, 0), &events);

    assert_eq!(ready.summary().event_count, 3);
    assert_eq!(read_events(&spool, &ready), events);
    assert_eq!(spool.list_ready().expect("inventory must pass").len(), 1);
}

#[test]
fn empty_segment_has_an_authenticated_footer() {
    let fixture = Fixture::new();
    let spool = fixture.open(limits());
    let ready = seal(&spool, header(input(1), 1, 0), &[]);

    assert_eq!(ready.summary().event_count, 0);
    assert_eq!(ready.summary().plaintext_bytes, 0);
    assert!(read_events(&spool, &ready).is_empty());
    assert!(ready.recovery_metadata().as_bytes().is_empty());
}

#[test]
fn recovery_metadata_round_trips_through_ready_and_delivered_inventory() {
    let fixture = Fixture::new();
    let spool = fixture.open(limits());
    let metadata = RecoveryMetadata::new(b"cursor-recovery-v1").expect("metadata must fit");
    let mut writer = spool
        .begin_segment(header(input(1), 1, 1))
        .expect("segment must begin");
    writer.append_event(b"event").expect("event must append");
    let ready = writer
        .seal_with_recovery_metadata(metadata.clone())
        .expect("segment must seal");

    assert_eq!(ready.recovery_metadata(), &metadata);
    let reopened = spool.list_ready().expect("ready inventory must pass");
    assert_eq!(reopened[0].recovery_metadata(), &metadata);
    assert_eq!(reopened[0].reference_digest(), ready.reference_digest());
    let delivered = spool
        .mark_delivered(&reopened[0])
        .expect("segment must become delivered");
    assert_eq!(delivered.recovery_metadata(), &metadata);
    assert_eq!(delivered.reference_digest(), ready.reference_digest());
}

#[test]
fn recovery_metadata_is_hard_bounded() {
    assert!(RecoveryMetadata::new([0x41; MAX_RECOVERY_METADATA_BYTES]).is_ok());
    let error = RecoveryMetadata::new(vec![0x41; MAX_RECOVERY_METADATA_BYTES + 1])
        .expect_err("oversize metadata must fail");

    assert_eq!(error.code(), "DBX-RS-SPOOL-LIMIT-0015");
}

#[test]
fn version_two_reserves_maximum_terminal_metadata_before_event_append() {
    let fixture = Fixture::new();
    let limits = SpoolLimits::new(512, 1_024, 2_048).expect("limits must work");
    let spool = fixture.open(limits);
    let mut exact = spool
        .begin_segment(header(input(1), 1, 1))
        .expect("segment must begin");
    exact
        .append_event(&[0x41; 34])
        .expect("exactly bounded event must fit");
    let ready = exact
        .seal_with_recovery_metadata(
            RecoveryMetadata::new([0x52; MAX_RECOVERY_METADATA_BYTES]).expect("metadata must fit"),
        )
        .expect("reserved terminal frames must fit");
    assert_eq!(ready.byte_len(), 512);

    let mut overflow = spool
        .begin_segment(header(input(1), 2, 1))
        .expect("second segment must begin");
    let error = overflow
        .append_event(&[0x41; 35])
        .expect_err("one extra event byte must exceed the segment");
    assert_eq!(error.code(), "DBX-RS-SPOOL-LIMIT-0004");
    overflow.abort().expect("failed writer must abort");
}

#[test]
fn recovery_metadata_tampering_blocks_inventory() {
    let fixture = Fixture::new();
    let spool = fixture.open(limits());
    let mut writer = spool
        .begin_segment(header(input(1), 1, 1))
        .expect("segment must begin");
    writer.append_event(b"event").expect("event must append");
    let ready = writer
        .seal_with_recovery_metadata(
            RecoveryMetadata::new(b"authenticated").expect("metadata must fit"),
        )
        .expect("segment must seal");
    let offsets = encrypted_frame_payload_offsets(&ready.path);
    let metadata_offset = offsets[offsets.len() - 2];
    mutate(&ready.path, metadata_offset, 0xff);

    assert!(spool.list_ready().is_err());
}

#[test]
fn reference_digest_binds_every_recovery_identity_component() {
    let fixture = Fixture::new();
    let spool = fixture.open(limits());
    let mut writer = spool
        .begin_segment(header(input(1), 1, 1))
        .expect("segment must begin");
    writer.append_event(b"event").expect("event must append");
    let ready = writer
        .seal_with_recovery_metadata(RecoveryMetadata::new(b"metadata").expect("metadata must fit"))
        .expect("segment must seal");
    let digest = ready.reference_digest();

    let mut changed_header = ready.clone();
    changed_header.header.configuration_generation += 1;
    assert_ne!(changed_header.reference_digest(), digest);
    let mut changed_segment = ready.clone();
    changed_segment.segment_id = SegmentId::new([0x77; 16]);
    assert_ne!(changed_segment.reference_digest(), digest);
    let mut changed_summary = ready.clone();
    changed_summary.summary.stream_digest[0] ^= 1;
    assert_ne!(changed_summary.reference_digest(), digest);
    let mut changed_metadata = ready.clone();
    changed_metadata.recovery_metadata =
        RecoveryMetadata::new(b"different").expect("metadata must fit");
    assert_ne!(changed_metadata.reference_digest(), digest);
    let mut changed_version = ready.clone();
    changed_version.format_version -= 1;
    assert_ne!(changed_version.reference_digest(), digest);

    let error = spool
        .mark_delivered(&changed_metadata)
        .expect_err("mismatched cached metadata must fail validation");
    assert_eq!(error.code(), "DBX-RS-SPOOL-FORMAT-0024");
}

#[test]
fn plaintext_event_never_occurs_in_the_segment_file() {
    let fixture = Fixture::new();
    let spool = fixture.open(limits());
    let marker = b"plaintext-event-marker-that-must-not-be-stored";
    let ready = seal(&spool, header(input(1), 1, 0), &[marker]);
    let stored = fs::read(&ready.path).expect("segment bytes must be readable");

    assert!(!stored.windows(marker.len()).any(|window| window == marker));
    assert!(!format!("{ready:?}").contains("plaintext-event-marker"));
}

#[test]
fn wrong_key_blocks_ready_inventory_without_deleting_it() {
    let fixture = Fixture::new();
    let spool = fixture.open(limits());
    let ready = seal(&spool, header(input(1), 1, 0), &[b"sensitive"]);
    let ready_path = ready.path.clone();
    drop(ready);
    drop(spool);

    let other_key = SpoolKey::load_or_create(&fixture.root.join("other/spool.key"))
        .expect("second key must open");
    let error = Spool::open(&fixture.spool_path, other_key, limits())
        .expect_err("wrong key must block inventory");

    assert_eq!(error.code(), "DBX-RS-SPOOL-CRYPTO-0002");
    assert!(ready_path.exists());
}

#[test]
fn prefix_frame_and_footer_tampering_fail_closed() {
    for corruption in ["prefix", "frame", "footer"] {
        let fixture = Fixture::new();
        let spool = fixture.open(limits());
        let ready = seal(&spool, header(input(1), 1, 0), &[b"event"]);
        let length = fs::metadata(&ready.path)
            .expect("segment metadata must exist")
            .len();
        let offset = match corruption {
            "prefix" => 0,
            "frame" => 230,
            "footer" => length - 1,
            _ => unreachable!(),
        };
        let original = {
            let mut file = fs::File::open(&ready.path).expect("segment must open");
            file.seek(SeekFrom::Start(offset))
                .expect("offset must seek");
            let mut byte = [0_u8; 1];
            file.read_exact(&mut byte).expect("byte must read");
            byte[0]
        };
        mutate(&ready.path, offset, original ^ 0xff);

        let error = spool
            .list_ready()
            .expect_err("tampering must block inventory");
        assert!(
            matches!(
                error.code(),
                "DBX-RS-SPOOL-FORMAT-0015" | "DBX-RS-SPOOL-CRYPTO-0003"
            ),
            "unexpected error: {error}"
        );
        assert!(ready.path.exists());
    }
}

#[test]
fn truncation_trailing_data_and_unknown_version_are_rejected() {
    for corruption in ["truncate", "trailing", "version"] {
        let fixture = Fixture::new();
        let spool = fixture.open(limits());
        let ready = seal(&spool, header(input(1), 1, 0), &[b"event"]);
        let length = fs::metadata(&ready.path)
            .expect("segment metadata must exist")
            .len();
        match corruption {
            "truncate" => {
                OpenOptions::new()
                    .write(true)
                    .open(&ready.path)
                    .expect("segment must open")
                    .set_len(length - 1)
                    .expect("segment must truncate");
            }
            "trailing" => {
                let mut file = OpenOptions::new()
                    .append(true)
                    .open(&ready.path)
                    .expect("segment must open");
                file.write_all(b"x").expect("trailing byte must append");
                file.sync_all().expect("trailing byte must synchronize");
            }
            "version" => mutate(&ready.path, 9, 3),
            _ => unreachable!(),
        }

        let error = spool
            .list_ready()
            .expect_err("malformed segment must block inventory");
        assert!(
            matches!(
                error.code(),
                "DBX-RS-SPOOL-FORMAT-0011"
                    | "DBX-RS-SPOOL-FORMAT-0016"
                    | "DBX-RS-SPOOL-FORMAT-0019"
            ),
            "unexpected error: {error}"
        );
        assert!(ready.path.exists());
    }
}

#[test]
fn declared_frame_length_cannot_exceed_remaining_file_bytes() {
    let fixture = Fixture::new();
    let spool = fixture.open(limits());
    let ready = seal(&spool, header(input(1), 1, 0), &[b"event"]);
    let declared = 8_192_u32;
    overwrite(
        &ready.path,
        crate::format::PREFIX_BYTES as u64,
        &declared.to_be_bytes(),
    );

    let error = spool
        .list_ready()
        .expect_err("a frame larger than the remaining file must fail before allocation");

    assert_eq!(error.code(), "DBX-RS-SPOOL-FORMAT-0019");
    assert!(ready.path.exists());
}

#[test]
fn declared_frame_length_cannot_consume_required_format_overhead() {
    let fixture = Fixture::new();
    let constrained = SpoolLimits::new(512, 1024, 2048).expect("limits are valid");
    let spool = fixture.open(constrained);
    let ready = seal(&spool, header(input(1), 1, 0), &[b"event"]);
    let declared =
        crate::format::maximum_ciphertext_frame_bytes(512, crate::format::FORMAT_VERSION)
            .checked_add(1)
            .and_then(|value| u32::try_from(value).ok())
            .expect("test frame length must fit");
    let file = OpenOptions::new()
        .write(true)
        .open(&ready.path)
        .expect("segment must open for extension");
    file.set_len(512).expect("segment must extend to its limit");
    file.sync_all().expect("segment extension must synchronize");
    overwrite(
        &ready.path,
        crate::format::PREFIX_BYTES as u64,
        &declared.to_be_bytes(),
    );

    let error = spool
        .list_ready()
        .expect_err("a frame consuming required metadata space must fail before allocation");

    assert_eq!(error.code(), "DBX-RS-SPOOL-FORMAT-0013");
    assert!(ready.path.exists());
}

#[test]
fn segment_limit_preserves_footer_space_and_aborts_cleanly() {
    let fixture = Fixture::new();
    let constrained = SpoolLimits::new(512, 1024, 2048).expect("limits are valid");
    let spool = fixture.open(constrained);
    let mut writer = spool
        .begin_segment(header(input(1), 1, 0))
        .expect("segment must begin");
    let error = writer
        .append_event(&vec![0x61; 400])
        .expect_err("oversized event must fail before write");

    assert_eq!(error.code(), "DBX-RS-SPOOL-LIMIT-0004");
    writer.abort().expect("writer must abort");
    assert_eq!(spool.usage().stored_bytes(), 0);
    assert_eq!(spool.usage().reserved_bytes(), 0);
    assert!(spool.list_ready().expect("inventory must pass").is_empty());
}

#[test]
fn per_input_and_global_quota_reserve_full_segments() {
    let fixture = Fixture::new();
    let quota = SpoolLimits::new(512, 1024, 1536).expect("limits are valid");
    let spool = fixture.open(quota);
    let first = spool
        .begin_segment(header(input(1), 1, 0))
        .expect("first reservation must pass");
    let second = spool
        .begin_segment(header(input(1), 1, 1))
        .expect("second reservation must pass");
    let input_error = spool
        .begin_segment(header(input(1), 1, 2))
        .expect_err("input quota must block third reservation");
    let third = spool
        .begin_segment(header(input(2), 1, 0))
        .expect("global final reservation must pass");
    let global_error = spool
        .begin_segment(header(input(3), 1, 0))
        .expect_err("global quota must block another input");

    assert_eq!(input_error.code(), "DBX-RS-SPOOL-QUOTA-0001");
    assert_eq!(global_error.code(), "DBX-RS-SPOOL-QUOTA-0002");
    assert_eq!(spool.usage().reserved_bytes(), 1536);
    drop((first, second, third));
    assert_eq!(spool.usage().reserved_bytes(), 0);
}

#[test]
fn concurrent_reservations_cannot_overcommit_global_quota() {
    let fixture = Fixture::new();
    let one = SpoolLimits::new(512, 512, 512).expect("limits are valid");
    let spool = Arc::new(fixture.open(one));
    let barrier = Arc::new(Barrier::new(3));
    let (sender, receiver) = mpsc::channel();
    let mut threads = Vec::new();
    for byte in [1_u8, 2] {
        let spool = Arc::clone(&spool);
        let barrier = Arc::clone(&barrier);
        let sender = sender.clone();
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            let reservation = spool.begin_segment(header(input(byte), 1, 0));
            sender.send(reservation.is_ok()).expect("result must send");
            barrier.wait();
            drop(reservation);
        }));
    }
    barrier.wait();
    barrier.wait();
    let results = [
        receiver.recv().expect("first result must arrive"),
        receiver.recv().expect("second result must arrive"),
    ];
    for thread in threads {
        thread.join().expect("reservation thread must finish");
    }

    assert_eq!(results.into_iter().filter(|success| *success).count(), 1);
    assert_eq!(spool.usage().reserved_bytes(), 0);
}

#[cfg(unix)]
#[test]
fn startup_moves_orphan_open_segment_to_private_quarantine() {
    let fixture = Fixture::new();
    let spool = fixture.open(limits());
    let writer = spool
        .begin_segment(header(input(1), 1, 0))
        .expect("segment must begin");
    std::mem::forget(writer);
    drop(spool);

    let reopened = fixture.open(limits());

    assert_eq!(reopened.recovered_open_segments(), 1);
    assert!(
        reopened
            .list_ready()
            .expect("ready inventory must pass")
            .is_empty()
    );
    assert!(reopened.usage().stored_bytes() > 0);
}

#[test]
fn ready_inventory_has_stable_input_and_batch_order() {
    let fixture = Fixture::new();
    let spool = fixture.open(limits());
    seal(&spool, header(input(2), 1, 0), &[b"fourth"]);
    seal(&spool, header(input(1), 2, 1), &[b"third"]);
    seal(&spool, header(input(1), 1, 1), &[b"second"]);
    seal(&spool, header(input(1), 1, 0), &[b"first"]);

    let order = spool
        .list_ready()
        .expect("inventory must pass")
        .into_iter()
        .map(|segment| {
            (
                segment.header().input_key,
                segment.header().batch_sequence,
                segment.header().segment_sequence,
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(
        order,
        vec![
            (input(1), 1, 0),
            (input(1), 1, 1),
            (input(1), 2, 1),
            (input(2), 1, 0),
        ]
    );
}

#[test]
fn delivered_segments_require_explicit_compaction() {
    let fixture = Fixture::new();
    let spool = fixture.open(limits());
    let ready = seal(&spool, header(input(1), 1, 0), &[b"event"]);
    let stored = spool.usage().stored_bytes();

    let delivered = spool
        .mark_delivered(&ready)
        .expect("ready segment must transition");
    assert_eq!(spool.usage().stored_bytes(), stored);
    assert!(spool.list_ready().expect("inventory must pass").is_empty());
    assert_eq!(
        spool
            .list_delivered()
            .expect("delivered inventory must pass")
            .len(),
        1
    );

    spool
        .compact_delivered(&delivered)
        .expect("explicit compaction must succeed");
    assert_eq!(spool.usage().stored_bytes(), 0);
    assert!(
        spool
            .list_delivered()
            .expect("delivered inventory must pass")
            .is_empty()
    );
}

#[cfg(unix)]
#[test]
fn created_paths_are_private_and_symlink_roots_are_rejected() {
    use std::os::unix::fs::{PermissionsExt, symlink};

    let fixture = Fixture::new();
    let spool = fixture.open(limits());
    let ready = seal(&spool, header(input(1), 1, 0), &[b"event"]);
    assert_eq!(
        fs::metadata(&fixture.key_path)
            .expect("key metadata must exist")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    for directory in [
        fixture.spool_path.clone(),
        fixture.spool_path.join(SEGMENTS_DIRECTORY),
        fixture.spool_path.join(QUARANTINE_DIRECTORY),
        ready
            .path
            .parent()
            .expect("input directory must exist")
            .into(),
    ] {
        assert_eq!(
            fs::metadata(directory)
                .expect("directory metadata must exist")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    assert_eq!(
        fs::metadata(&ready.path)
            .expect("segment metadata must exist")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );

    let real = fixture.root.join("real-spool");
    fs::create_dir_all(&real).expect("real directory must exist");
    let linked = fixture.root.join("linked-spool");
    symlink(&real, &linked).expect("spool symlink must be created");
    let key = SpoolKey::load_or_create(&fixture.root.join("linked-key/spool.key"))
        .expect("linked test key must open");
    let error = Spool::open(&linked, key, limits()).expect_err("symlink root must fail closed");
    assert_eq!(error.code(), "DBX-RS-SPOOL-PATH-0003");

    let ancestor_target = fixture.root.join("ancestor-target");
    fs::create_dir_all(&ancestor_target).expect("ancestor target must exist");
    let ancestor_link = fixture.root.join("ancestor-link");
    symlink(&ancestor_target, &ancestor_link).expect("ancestor symlink must be created");
    let key = SpoolKey::load_or_create(&fixture.root.join("ancestor-key/spool.key"))
        .expect("ancestor test key must open");
    let nested_spool = ancestor_link.join("nested/spool");
    let error =
        Spool::open(&nested_spool, key, limits()).expect_err("symlink ancestor must fail closed");
    assert_eq!(error.code(), "DBX-RS-SPOOL-PATH-0003");
    assert!(!ancestor_target.join("nested").exists());

    let error = SpoolKey::load_or_create(&ancestor_link.join("nested/spool.key"))
        .expect_err("spool key symlink ancestor must fail closed");
    assert_eq!(error.code(), "DBX-RS-SPOOL-PATH-0003");
    assert!(!ancestor_target.join("nested").exists());
}
