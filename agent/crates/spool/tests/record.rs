//! Record encoding, independent CRC and mutation-on-error checks.

mod support;
use ricevanta_spool::{Error, MAX_PAYLOAD_LEN, Record, encode_record};

#[test]
fn independent_crc_check_value() {
    assert_eq!(support::crc(&[b"123456789"]), 0xe3069283);
    assert_eq!(support::crc(&[b"1234", b"56789"]), 0xe3069283);
}

#[test]
fn empty_binary_and_full_width_sequences() {
    for sequence in [0, 0x0807060504030201, u64::MAX] {
        for payload in [&b""[..], &b"\x00\xff\r\n123456789"[..]] {
            let mut output = vec![0xa5; 16 + payload.len() + 9];
            let n = encode_record(Record { sequence, payload }, &mut output).unwrap();
            assert_eq!(n, 16 + payload.len());
            assert_eq!(&output[..4], &(payload.len() as u32).to_le_bytes());
            assert_eq!(
                &output[4..8],
                &support::crc(&[&sequence.to_le_bytes(), payload]).to_le_bytes()
            );
            assert_eq!(&output[8..16], &sequence.to_le_bytes());
            assert_eq!(&output[16..n], payload);
            assert_eq!(&output[n..], &[0xa5; 9]);
        }
    }
}

#[test]
fn fixture_checksum_and_asymmetric_bytes() {
    let mut out = [0; 18];
    encode_record(
        Record {
            sequence: 41,
            payload: b"{}",
        },
        &mut out,
    )
    .unwrap();
    assert_eq!(
        out,
        [
            2, 0, 0, 0, 0x71, 0x1d, 0xcc, 0xa8, 41, 0, 0, 0, 0, 0, 0, 0, 0x7b, 0x7d
        ]
    );
    let mut out = [0; 19];
    encode_record(
        Record {
            sequence: 0x2132435465768798,
            payload: b"abc",
        },
        &mut out,
    )
    .unwrap();
    assert_eq!(
        out,
        [
            3, 0, 0, 0, 0x0b, 0xc9, 0xb4, 0x7e, 0x98, 0x87, 0x76, 0x65, 0x54, 0x43, 0x32, 0x21,
            b'a', b'b', b'c'
        ]
    );
}

#[test]
fn every_short_buffer_preserved_and_exact_buffer_succeeds() {
    let record = Record {
        sequence: 0,
        payload: b"abc",
    };
    for actual in 0..=19 {
        let mut output = vec![0x5a; actual];
        let before = output.clone();
        let result = encode_record(record, &mut output);
        if actual < 19 {
            assert_eq!(result, Err(Error::OutputTooSmall { needed: 19, actual }));
            assert_eq!(output, before);
        } else {
            assert_eq!(result, Ok(19));
        }
    }
}

#[test]
fn payload_cap_and_error_precedence_preserve_output() {
    for length in [MAX_PAYLOAD_LEN - 1, MAX_PAYLOAD_LEN, MAX_PAYLOAD_LEN + 1] {
        let payload = vec![0x9a; length];
        for actual in [3, length + 16] {
            let mut output = vec![0x5a; actual];
            let before = output.clone();
            let result = encode_record(
                Record {
                    sequence: u64::MAX,
                    payload: &payload,
                },
                &mut output,
            );
            if length > MAX_PAYLOAD_LEN {
                assert_eq!(result, Err(Error::PayloadTooLarge { length }));
                assert_eq!(output, before);
            } else if actual < length + 16 {
                assert_eq!(
                    result,
                    Err(Error::OutputTooSmall {
                        needed: length + 16,
                        actual
                    })
                );
                assert_eq!(output, before);
            } else {
                assert_eq!(result, Ok(length + 16));
                assert_eq!(
                    &output[4..8],
                    &support::crc(&[&u64::MAX.to_le_bytes(), &payload]).to_le_bytes()
                );
                assert_eq!(&output[16..], &payload);
            }
        }
    }
}
