//! Recovery boundaries, ordered failures and immutable borrowed prefixes.

mod support;
use ricevanta_spool::{Error, MAX_PAYLOAD_LEN, TailIssue, TailKind, recover};

#[test]
fn every_header_truncation_and_header_precedence() {
    let good = support::segment(0, &[]);
    for length in 0..32 {
        let input = vec![0xff; length];
        assert_eq!(
            recover(&input).unwrap_err(),
            Error::HeaderTooShort { actual: length }
        );
    }
    let mut bad = vec![0xff; 32];
    assert_eq!(recover(&bad).unwrap_err(), Error::Magic);
    bad[..4].copy_from_slice(&good[..4]);
    assert_eq!(recover(&bad).unwrap_err(), Error::Version { found: 65535 });
    bad[4..6].copy_from_slice(&good[4..6]);
    assert_eq!(recover(&bad).unwrap_err(), Error::Class { found: 255 });
    bad[6] = 1;
    bad[8..16].fill(0);
    assert_eq!(recover(&bad).unwrap_err(), Error::Reserved { found: 255 });
    bad[7] = 0;
    bad.extend_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(recover(&bad).unwrap_err(), Error::StreamEpoch);
}

#[test]
fn final_record_truncation_at_every_byte() {
    let input = support::segment(7, &[(7, b"first"), (8, b"second")]);
    let boundary = 32 + 16 + 5;
    for length in boundary..=input.len() {
        let prefix = &input[..length];
        let before = prefix.to_vec();
        let recovered = recover(prefix).unwrap();
        assert_eq!(prefix, before);
        if length == input.len() {
            assert_eq!(recovered.record_count(), 2);
            assert_eq!(recovered.next_sequence(), Some(9));
            assert_eq!(recovered.tail(), None);
            assert_eq!(recovered.valid_len(), length);
        } else {
            assert_eq!(recovered.record_count(), 1);
            assert_eq!(recovered.valid_len(), boundary);
            assert_eq!(recovered.next_sequence(), Some(8));
            let tail = if length == boundary {
                None
            } else {
                Some(TailIssue {
                    offset: boundary,
                    kind: TailKind::Incomplete,
                })
            };
            assert_eq!(recovered.tail(), tail);
        }
    }
}

#[test]
fn length_completeness_crc_and_sequence_precedence() {
    for length in [MAX_PAYLOAD_LEN as u32 + 1, u32::MAX] {
        let mut input = support::segment(0, &[]);
        input.extend_from_slice(&length.to_le_bytes());
        assert_eq!(
            recover(&input).unwrap_err(),
            Error::PayloadTooLarge {
                length: length as usize
            }
        );
    }
    let mut input = support::segment(0, &[(1, b"abc")]);
    input[36] ^= 1;
    assert_eq!(
        recover(&input[..input.len() - 1]).unwrap().tail(),
        Some(TailIssue {
            offset: 32,
            kind: TailKind::Incomplete
        })
    );
    assert_eq!(
        recover(&input).unwrap().tail(),
        Some(TailIssue {
            offset: 32,
            kind: TailKind::Checksum
        })
    );
    let mut input = support::segment(0, &[(0, b"a"), (2, b"b"), (3, b"c")]);
    input[70] ^= 1;
    assert_eq!(
        recover(&input).unwrap_err(),
        Error::Sequence {
            offset: 49,
            expected: Some(1),
            found: 2
        }
    );
}

#[test]
fn corrupt_record_discards_entire_suffix() {
    for bad_offset in [32, 49] {
        let mut input = support::segment(0, &[(0, b"a"), (1, b"b"), (2, b"c")]);
        input[bad_offset + 4] ^= 1;
        input.extend_from_slice(&u32::MAX.to_le_bytes());
        let before = input.clone();
        let recovered = recover(&input).unwrap();
        assert_eq!(input, before);
        assert_eq!(recovered.valid_len(), bad_offset);
        assert_eq!(recovered.record_count(), (bad_offset - 32) / 17);
        assert_eq!(
            recovered.tail(),
            Some(TailIssue {
                offset: bad_offset,
                kind: TailKind::Checksum
            })
        );
        for record in recovered.records() {
            support::assert_borrowed(&input, bad_offset, record);
        }
    }
}

#[test]
fn sequence_errors_are_fatal() {
    for found in [0, 2, 9, u64::MAX] {
        let input = support::segment(1, &[(found, b"opaque")]);
        assert_eq!(
            recover(&input).unwrap_err(),
            Error::Sequence {
                offset: 32,
                expected: Some(1),
                found
            }
        );
    }
    for found in [0, 1, 3] {
        let input = support::segment(1, &[(1, b""), (found, b"")]);
        assert_eq!(
            recover(&input).unwrap_err(),
            Error::Sequence {
                offset: 48,
                expected: Some(2),
                found
            }
        );
    }
}

#[test]
fn exhaustion_respects_eof_partial_crc_and_sequence_order() {
    let clean = support::segment(u64::MAX, &[(u64::MAX, b"")]);
    assert_eq!(recover(&clean).unwrap().next_sequence(), None);
    assert_eq!(recover(&clean).unwrap().tail(), None);
    let extra = support::record(0, b"tail");
    for cut in 1..extra.len() {
        let mut input = clean.clone();
        input.extend_from_slice(&extra[..cut]);
        let recovered = recover(&input).unwrap();
        assert_eq!(recovered.next_sequence(), None);
        assert_eq!(recovered.valid_len(), clean.len());
        assert_eq!(
            recovered.tail(),
            Some(TailIssue {
                offset: clean.len(),
                kind: TailKind::Incomplete
            })
        );
    }
    let mut input = clean.clone();
    input.extend_from_slice(&extra);
    assert_eq!(
        recover(&input).unwrap_err(),
        Error::Sequence {
            offset: clean.len(),
            expected: None,
            found: 0
        }
    );
    input[clean.len() + 4] ^= 1;
    assert_eq!(
        recover(&input).unwrap().tail(),
        Some(TailIssue {
            offset: clean.len(),
            kind: TailKind::Checksum
        })
    );
}

#[test]
fn payload_boundary_and_sealing_thresholds() {
    for length in [MAX_PAYLOAD_LEN - 1, MAX_PAYLOAD_LEN] {
        let payload = vec![0xfe; length];
        let input = support::segment(0, &[(0, &payload)]);
        let recovered = recover(&input).unwrap();
        assert_eq!(recovered.record_count(), 1);
        assert_eq!(recovered.valid_len(), input.len());
        assert_eq!(recovered.records().next().unwrap().payload, payload);
    }
    let payload = vec![0; MAX_PAYLOAD_LEN + 1];
    let input = support::segment(0, &[(0, &payload)]);
    assert_eq!(
        recover(&input).unwrap_err(),
        Error::PayloadTooLarge {
            length: payload.len()
        }
    );
    let payload = vec![0; MAX_PAYLOAD_LEN];
    let input = support::segment(
        0,
        &[(0, &payload), (1, &payload), (2, &payload), (3, &payload)],
    );
    assert!(input.len() > 4 * 1024 * 1024);
    let recovered = recover(&input).unwrap();
    assert_eq!(recovered.record_count(), 4);
    assert_eq!(recovered.valid_len(), input.len());
    let mut input = support::segment(0, &[]);
    for sequence in 0..5001 {
        input.extend(support::record(sequence, b""));
    }
    let recovered = recover(&input).unwrap();
    assert_eq!(recovered.record_count(), 5001);
    assert_eq!(recovered.next_sequence(), Some(5001));
    assert_eq!(recovered.valid_len(), input.len());
}

#[test]
fn iteration_borrows_input_and_outlives_summary() {
    let input = support::segment(0, &[(0, b"\xff\n"), (1, b"")]);
    let iterator = {
        let recovered = recover(&input).unwrap();
        recovered.records()
    };
    let actual: Vec<_> = iterator.collect();
    let recovered = recover(&input).unwrap();
    assert_eq!(recovered.records().collect::<Vec<_>>(), actual);
    for record in actual {
        support::assert_borrowed(&input, input.len(), record);
    }
}
