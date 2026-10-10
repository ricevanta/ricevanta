//! Header byte contract and class parity checks.

use ricevanta_spool::{
    Error, FORMAT_VERSION, HEADER_LEN, Header, MAX_PAYLOAD_LEN, RECORD_HEADER_LEN, SpoolClass,
    encode_header,
};

#[test]
fn class_values_names_and_unknown_bytes() {
    let classes = [
        (SpoolClass::Raw, "raw"),
        (SpoolClass::Context, "context"),
        (SpoolClass::Lineage, "lineage"),
        (SpoolClass::Findings, "findings"),
        (SpoolClass::Audit, "audit"),
    ];
    for value in 0..=255u8 {
        if (1..=5).contains(&value) {
            let (class, name) = classes[usize::from(value - 1)];
            assert_eq!(class as u8, value);
            assert_eq!(class.as_str(), name);
            assert_eq!(SpoolClass::try_from(value), Ok(class));
        } else {
            assert_eq!(
                SpoolClass::try_from(value),
                Err(Error::Class { found: value })
            );
        }
    }
}

#[test]
fn canonical_header_bytes_and_constants() {
    assert_eq!(
        (
            FORMAT_VERSION,
            HEADER_LEN,
            RECORD_HEADER_LEN,
            MAX_PAYLOAD_LEN
        ),
        (1, 32, 16, 1_048_576)
    );
    let header = Header {
        class: SpoolClass::Audit,
        stream_epoch: 0x0807060504030201,
        segment_id: 0x1817161514131211,
        first_sequence: 0x2827262524232221,
    };
    let expected = [
        0x52, 0x56, 0x53, 0x50, 1, 0, 5, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0x11, 0x12, 0x13, 0x14, 0x15,
        0x16, 0x17, 0x18, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    ];
    assert_eq!(encode_header(header), Ok(expected));
}

#[test]
fn zero_counters_maxima_and_zero_epoch() {
    for class in [
        SpoolClass::Raw,
        SpoolClass::Context,
        SpoolClass::Lineage,
        SpoolClass::Findings,
        SpoolClass::Audit,
    ] {
        let zero = Header {
            class,
            stream_epoch: 1,
            segment_id: 0,
            first_sequence: 0,
        };
        let bytes = encode_header(zero).unwrap();
        assert_eq!(&bytes[..8], &[0x52, 0x56, 0x53, 0x50, 1, 0, class as u8, 0]);
        assert_eq!(&bytes[8..16], &[1, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&bytes[16..], &[0; 16]);
        let max = Header {
            stream_epoch: u64::MAX,
            segment_id: u64::MAX,
            first_sequence: u64::MAX,
            ..zero
        };
        assert_eq!(&encode_header(max).unwrap()[8..], &[255; 24]);
        assert_eq!(
            encode_header(Header {
                stream_epoch: 0,
                ..zero
            }),
            Err(Error::StreamEpoch)
        );
    }
}

#[test]
fn error_traits_and_variants() {
    let errors = [
        Error::HeaderTooShort { actual: 3 },
        Error::Magic,
        Error::Version { found: 2 },
        Error::Class { found: 0 },
        Error::Reserved { found: 7 },
        Error::StreamEpoch,
        Error::PayloadTooLarge { length: 1_048_577 },
        Error::OutputTooSmall {
            needed: 16,
            actual: 0,
        },
        Error::Sequence {
            offset: 32,
            expected: None,
            found: 0,
        },
    ];
    for error in errors {
        let object: &dyn std::error::Error = &error;
        assert!(object.source().is_none());
        assert!(!object.to_string().is_empty());
        assert_eq!(error, error);
        assert!(!format!("{error:?}").is_empty());
    }
    assert!(matches!(
        SpoolClass::try_from(255),
        Err(Error::Class { found: 255 })
    ));
}
