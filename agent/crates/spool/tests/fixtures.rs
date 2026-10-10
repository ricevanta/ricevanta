//! Execute every approved shared fixture and re-encode each accepted prefix.

mod support;
use ricevanta_spool::{encode_header, encode_record, recover};
use support::{Expected, fixture_data::FIXTURES};

#[test]
fn every_shared_fixture() {
    for fixture in FIXTURES {
        let input = fixture.input.to_vec();
        let before = input.clone();
        let result = recover(&input);
        assert_eq!(input, before, "{} input mutation", fixture.id);
        match &fixture.expected {
            Expected::Error(expected) => {
                assert_eq!(result.unwrap_err(), *expected, "{}", fixture.id)
            }
            Expected::Success {
                header,
                records,
                valid_len,
                next_sequence,
                tail,
            } => {
                let recovered = result.unwrap_or_else(|e| panic!("{}: {e:?}", fixture.id));
                assert_eq!(recovered.header(), *header, "{}", fixture.id);
                assert_eq!(recovered.valid_len(), *valid_len, "{}", fixture.id);
                assert_eq!(recovered.record_count(), records.len(), "{}", fixture.id);
                assert_eq!(recovered.next_sequence(), *next_sequence, "{}", fixture.id);
                assert_eq!(recovered.tail(), *tail, "{}", fixture.id);
                let actual: Vec<_> = recovered.records().collect();
                assert_eq!(actual, *records, "{}", fixture.id);
                assert_eq!(
                    recovered.records().collect::<Vec<_>>(),
                    actual,
                    "{} repeat",
                    fixture.id
                );
                let mut offset = 32;
                for record in &actual {
                    support::assert_borrowed(&input, *valid_len, *record);
                    let stored =
                        u32::from_le_bytes(input[offset + 4..offset + 8].try_into().unwrap());
                    assert_eq!(
                        stored,
                        support::crc(&[&record.sequence.to_le_bytes(), record.payload]),
                        "{} independent CRC",
                        fixture.id
                    );
                    offset += 16 + record.payload.len();
                }
                assert_eq!(offset, *valid_len, "{}", fixture.id);
                let mut encoded = encode_header(*header).unwrap().to_vec();
                for record in *records {
                    let mut output = vec![0; 16 + record.payload.len()];
                    let length = encode_record(*record, &mut output).unwrap();
                    encoded.extend_from_slice(&output[..length]);
                }
                assert_eq!(encoded, input[..*valid_len], "{} re-encoding", fixture.id);
            }
        }
    }
    eprintln!("executed all {} shared fixtures", FIXTURES.len());
}
