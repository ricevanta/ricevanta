//! Independent test oracles and shared segment construction.

// Each integration target uses a different subset of these test-only helpers.
#![allow(dead_code)]

// This helper deliberately avoids the production checksum implementation.
pub fn crc(parts: &[&[u8]]) -> u32 {
    let mut register = u32::MAX;
    for bytes in parts {
        for byte in *bytes {
            register ^= u32::from(*byte);
            for _ in 0..8 {
                register = (register >> 1) ^ if register & 1 == 1 { 0x82f63b78 } else { 0 };
            }
        }
    }
    register ^ u32::MAX
}

use ricevanta_spool::{Error, Header, Record, SpoolClass, TailIssue};

pub mod fixture_data;

pub struct Fixture {
    pub id: &'static str,
    pub input: &'static [u8],
    pub expected: Expected,
}

pub enum Expected {
    Error(Error),
    Success {
        header: Header,
        records: &'static [Record<'static>],
        valid_len: usize,
        next_sequence: Option<u64>,
        tail: Option<TailIssue>,
    },
}

pub fn header(first_sequence: u64) -> Header {
    Header {
        class: SpoolClass::Raw,
        stream_epoch: 1,
        segment_id: 0,
        first_sequence,
    }
}

// Independent record construction prevents an encoder bug from masking recovery defects.
pub fn record(sequence: u64, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&crc(&[&sequence.to_le_bytes(), payload]).to_le_bytes());
    bytes.extend_from_slice(&sequence.to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

pub fn segment(first_sequence: u64, records: &[(u64, &[u8])]) -> Vec<u8> {
    let mut bytes = b"RVSP\x01\x00\x01\x00".to_vec();
    bytes.extend_from_slice(&1u64.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&first_sequence.to_le_bytes());
    for (sequence, payload) in records {
        bytes.extend(record(*sequence, payload));
    }
    bytes
}

pub fn assert_borrowed(input: &[u8], valid_len: usize, record: Record<'_>) {
    let start = input.as_ptr() as usize;
    let payload = record.payload.as_ptr() as usize;
    assert!(payload >= start + 32);
    assert!(payload <= start + valid_len);
    assert!(record.payload.len() <= start + valid_len - payload);
}

pub fn check_recovery_invariants(input: &[u8], context: &str) {
    use ricevanta_spool::{MAX_PAYLOAD_LEN, TailKind, recover};
    let before = input.to_vec();
    let result = std::panic::catch_unwind(|| recover(input));
    assert!(result.is_ok(), "{context}: recovery panicked");
    assert!(input == before, "{context}: input changed");
    let Ok(recovered) = result.unwrap() else {
        return;
    };
    let valid_len = recovered.valid_len();
    assert!(
        (32..=input.len()).contains(&valid_len),
        "{context}: prefix bounds"
    );
    let header = recovered.header();
    assert_eq!(
        &input[..8],
        &[b'R', b'V', b'S', b'P', 1, 0, header.class as u8, 0],
        "{context}: canonical header"
    );
    assert_ne!(header.stream_epoch, 0, "{context}: nonzero epoch");
    assert_eq!(
        &input[8..16],
        &header.stream_epoch.to_le_bytes(),
        "{context}: stored epoch"
    );
    assert_eq!(
        &input[16..24],
        &header.segment_id.to_le_bytes(),
        "{context}: stored segment"
    );
    assert_eq!(
        &input[24..32],
        &header.first_sequence.to_le_bytes(),
        "{context}: stored first sequence"
    );
    match recovered.tail() {
        None => assert_eq!(valid_len, input.len(), "{context}: clean EOF length"),
        Some(tail) => {
            assert_eq!(tail.offset, valid_len, "{context}: tail boundary");
            let suffix = &input[valid_len..];
            assert!(!suffix.is_empty(), "{context}: nonempty rejected suffix");
            if suffix.len() < 4 {
                assert_eq!(
                    tail.kind,
                    TailKind::Incomplete,
                    "{context}: short length tail"
                );
            } else {
                let length = u32::from_le_bytes(suffix[..4].try_into().unwrap()) as usize;
                assert!(
                    length <= MAX_PAYLOAD_LEN,
                    "{context}: unsupported tail length"
                );
                if suffix.len() < 16 + length {
                    assert_eq!(tail.kind, TailKind::Incomplete, "{context}: torn body tail");
                } else {
                    assert_eq!(
                        tail.kind,
                        TailKind::Checksum,
                        "{context}: complete rejected record"
                    );
                    let stored = u32::from_le_bytes(suffix[4..8].try_into().unwrap());
                    assert_ne!(
                        stored,
                        crc(&[&suffix[8..16 + length]]),
                        "{context}: checksum tail oracle"
                    );
                }
            }
        }
    }
    let records: Vec<_> = recovered.records().collect();
    assert_eq!(records.len(), recovered.record_count(), "{context}: count");
    let mut offset = 32;
    let mut expected = Some(header.first_sequence);
    for record in &records {
        assert_eq!(
            expected,
            Some(record.sequence),
            "{context}: contiguous sequence"
        );
        assert!(
            record.payload.len() <= MAX_PAYLOAD_LEN,
            "{context}: payload cap"
        );
        let needed = 16 + record.payload.len();
        assert!(needed <= valid_len - offset, "{context}: record bounds");
        let length = u32::from_le_bytes(input[offset..offset + 4].try_into().unwrap()) as usize;
        assert_eq!(length, record.payload.len(), "{context}: stored length");
        let stored = u32::from_le_bytes(input[offset + 4..offset + 8].try_into().unwrap());
        let sequence = u64::from_le_bytes(input[offset + 8..offset + 16].try_into().unwrap());
        assert_eq!(sequence, record.sequence, "{context}: stored sequence");
        assert_eq!(
            stored,
            crc(&[&sequence.to_le_bytes(), record.payload]),
            "{context}: accepted CRC oracle"
        );
        let pointer = record.payload.as_ptr() as usize;
        let start = input.as_ptr() as usize;
        assert_eq!(
            pointer,
            start + offset + 16,
            "{context}: borrowed payload location"
        );
        assert!(
            pointer + record.payload.len() <= start + valid_len,
            "{context}: borrowed payload bounds"
        );
        assert!(
            record.payload == &input[offset + 16..offset + needed],
            "{context}: exact stored payload"
        );
        offset += needed;
        expected = sequence.checked_add(1);
    }
    assert_eq!(offset, valid_len, "{context}: iterator consumes prefix");
    assert_eq!(
        expected,
        recovered.next_sequence(),
        "{context}: next sequence summary"
    );
    let rescanned =
        recover(&input[..valid_len]).unwrap_or_else(|e| panic!("{context}: rescan failed: {e:?}"));
    assert_eq!(rescanned.header(), header, "{context}: rescan header");
    assert_eq!(rescanned.tail(), None, "{context}: rescan clean EOF");
    assert_eq!(rescanned.valid_len(), valid_len, "{context}: rescan length");
    assert_eq!(
        rescanned.record_count(),
        records.len(),
        "{context}: rescan count"
    );
    assert_eq!(
        rescanned.next_sequence(),
        expected,
        "{context}: rescan next sequence"
    );
    assert!(
        rescanned.records().eq(records.iter().copied()),
        "{context}: rescan records"
    );
    assert!(
        recovered.records().eq(records.iter().copied()),
        "{context}: repeat records"
    );
}
