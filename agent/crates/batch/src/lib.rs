//! Complete spool segments sealed for the event upload protocol.

mod compress;

use std::fmt;

/// Maximum records in one batch.
pub const MAX_RECORDS: usize = 5_000;
/// Maximum payload-plus-LF byte total.
pub const MAX_NDJSON_BYTES: usize = 4_194_304;
/// Maximum complete raw segment length, including framing.
pub const MAX_SEGMENT_BYTES: usize = 4_269_336;

/// First framing defect in an opaque record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineFraming {
    /// Empty or only spaces and tabs.
    Blank,
    /// Initial UTF-8 byte order mark.
    Bom,
    /// Literal line feed.
    Lf,
    /// Literal carriage return.
    Cr,
}

/// Sealing failure, with no partial output or input mutation.
#[derive(Debug)]
pub enum Error {
    /// Input exceeds the entry bound, checked before recovery.
    SegmentTooLarge {
        /// Supplied byte length.
        length: usize,
    },
    /// Fatal spool error, preserved unchanged.
    Spool(ricevanta_spool::Error),
    /// Recovery rejected a suffix. The valid prefix is never sealed.
    Tail(ricevanta_spool::TailIssue),
    /// Complete segment has no records.
    Empty,
    /// Record count exceeds the writer ceiling.
    RecordCount {
        /// Recovered count.
        count: usize,
    },
    /// First record with invalid line framing.
    LineFraming {
        /// Zero-based record position.
        index: usize,
        /// First framing defect.
        kind: LineFraming,
    },
    /// Payload and LF would exceed the decoded byte ceiling.
    DecodedLimit {
        /// Zero-based record position.
        index: usize,
    },
    /// Encoder construction, configuration or compression failed.
    Compression(std::io::Error),
    /// Complete body exceeds the compressed ceiling.
    CompressedLimit {
        /// Complete body length.
        length: usize,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SegmentTooLarge { length } => write!(f, "segment too large: {length}"),
            Self::Spool(_) => f.write_str("spool validation failed"),
            Self::Tail(_) => f.write_str("spool tail rejected"),
            Self::Empty => f.write_str("empty segment"),
            Self::RecordCount { count } => write!(f, "record count exceeded: {count}"),
            Self::LineFraming { index, kind } => write!(f, "line framing at {index}: {kind:?}"),
            Self::DecodedLimit { index } => write!(f, "decoded limit at {index}"),
            Self::Compression(_) => f.write_str("compression failed"),
            Self::CompressedLimit { length } => write!(f, "compressed limit exceeded: {length}"),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Spool(e) => Some(e),
            Self::Compression(e) => Some(e),
            _ => None,
        }
    }
}

/// Completed owned header and body. Debug exposes only byte lengths.
///
/// Accessors preserve the association; `into_parts` transfers that duty to the caller.
pub struct SealedBatch {
    header: String,
    body: Vec<u8>,
}
impl fmt::Debug for SealedBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SealedBatch")
            .field("header_len", &self.header.len())
            .field("body_len", &self.body.len())
            .finish()
    }
}
impl SealedBatch {
    /// Canonical ordered header value, without a field name or newline.
    pub fn header_value(&self) -> &str {
        &self.header
    }
    /// Complete descriptor prefix and exactly one zstd frame.
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    /// Transfers both completed allocations to the caller.
    pub fn into_parts(self) -> (String, Vec<u8>) {
        (self.header, self.body)
    }
}

/// Validates one complete raw spool segment and seals all records atomically.
///
/// Checks input size, spool recovery, tail, count, then each record's framing
/// and payload-plus-LF total in that order. Payload bytes stay opaque. Failures
/// return no prefix and never mutate input. Success owns both allocations.
/// No filesystem, transport, JSON validation or durability guarantee is made.
pub fn seal(segment: &[u8]) -> Result<SealedBatch, Error> {
    let Prepared {
        header,
        descriptor,
        plain,
    } = prepare(segment)?;
    let body = compress::compress(&plain, &descriptor)?;
    drop(plain);
    Ok(SealedBatch { header, body })
}

struct Prepared {
    header: String,
    descriptor: [u8; 48],
    plain: Vec<u8>,
}
fn prepare(segment: &[u8]) -> Result<Prepared, Error> {
    if segment.len() > MAX_SEGMENT_BYTES {
        return Err(Error::SegmentTooLarge {
            length: segment.len(),
        });
    }
    let recovery = ricevanta_spool::recover(segment).map_err(Error::Spool)?;
    if let Some(tail) = recovery.tail() {
        return Err(Error::Tail(tail));
    }
    let count = recovery.record_count();
    if count == 0 {
        return Err(Error::Empty);
    }
    if count > MAX_RECORDS {
        return Err(Error::RecordCount { count });
    }
    let mut total = 0;
    let mut last = 0;
    for (index, record) in recovery.records().enumerate() {
        let p = record.payload;
        let kind = if p.iter().all(|b| matches!(b, b' ' | b'\t')) {
            Some(LineFraming::Blank)
        } else if p.starts_with(&[0xef, 0xbb, 0xbf]) {
            Some(LineFraming::Bom)
        } else if p.contains(&b'\n') {
            Some(LineFraming::Lf)
        } else if p.contains(&b'\r') {
            Some(LineFraming::Cr)
        } else {
            None
        };
        if let Some(kind) = kind {
            return Err(Error::LineFraming { index, kind });
        }
        let added = p.len() + 1;
        if added > MAX_NDJSON_BYTES - total {
            return Err(Error::DecodedLimit { index });
        }
        total += added;
        last = record.sequence;
    }
    let h = recovery.header();
    let header = format!(
        "v=1;class={};epoch={};segment={};first={};last={};count={}",
        h.class.as_str(),
        h.stream_epoch,
        h.segment_id,
        h.first_sequence,
        last,
        count
    );
    let mut descriptor = [0; 48];
    descriptor[..4].copy_from_slice(&0x184d2a50u32.to_le_bytes());
    descriptor[4..8].copy_from_slice(&40u32.to_le_bytes());
    descriptor[8] = 1;
    descriptor[9] = h.class as u8;
    descriptor[12..20].copy_from_slice(&h.stream_epoch.to_le_bytes());
    descriptor[20..28].copy_from_slice(&h.segment_id.to_le_bytes());
    descriptor[28..36].copy_from_slice(&h.first_sequence.to_le_bytes());
    descriptor[36..44].copy_from_slice(&last.to_le_bytes());
    descriptor[44..48].copy_from_slice(&(count as u32).to_le_bytes());
    let mut plain = Vec::with_capacity(total);
    for record in recovery.records() {
        plain.extend_from_slice(record.payload);
        plain.push(b'\n');
    }
    Ok(Prepared {
        header,
        descriptor,
        plain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ricevanta_spool::{Error as SpoolError, Header, SpoolClass, TailKind};

    fn header(first: u64) -> Header {
        Header {
            class: SpoolClass::Raw,
            stream_epoch: 1,
            segment_id: 0,
            first_sequence: first,
        }
    }
    fn crc(bytes: &[u8]) -> u32 {
        let mut c = !0u32;
        for b in bytes {
            c ^= u32::from(*b);
            for _ in 0..8 {
                c = (c >> 1) ^ (0x82f63b78 & 0u32.wrapping_sub(c & 1));
            }
        }
        !c
    }
    fn append(b: &mut Vec<u8>, sequence: u64, payload: &[u8]) {
        let mut data = sequence.to_le_bytes().to_vec();
        data.extend_from_slice(payload);
        b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        b.extend_from_slice(&crc(&data).to_le_bytes());
        b.extend_from_slice(&data);
    }
    fn segment(h: Header, payloads: &[&[u8]]) -> Vec<u8> {
        let mut b = ricevanta_spool::encode_header(h).unwrap().to_vec();
        for (i, p) in payloads.iter().enumerate() {
            append(&mut b, h.first_sequence + i as u64, p);
        }
        b
    }
    fn failure(b: &[u8]) -> Error {
        let original = b.to_vec();
        let err = prepare(b).err().unwrap();
        assert_eq!(b, original);
        err
    }
    #[test]
    fn rejects_segment_size() {
        assert!(
            matches!(failure(&vec![0; MAX_SEGMENT_BYTES + 1]), Error::SegmentTooLarge { length } if length == MAX_SEGMENT_BYTES + 1)
        );
        assert!(matches!(
            failure(&vec![0; MAX_SEGMENT_BYTES]),
            Error::Spool(SpoolError::Magic)
        ));
    }
    #[test]
    fn rejects_spool_errors() {
        assert!(matches!(
            failure(&[]),
            Error::Spool(SpoolError::HeaderTooShort { actual: 0 })
        ));
        for (offset, value) in [(0, 0), (4, 2), (6, 0), (7, 1), (8, 0)] {
            let mut b = segment(header(0), &[b"x"]);
            b[offset] = value;
            let expected = match offset {
                0 => SpoolError::Magic,
                4 => SpoolError::Version { found: 2 },
                6 => SpoolError::Class { found: 0 },
                7 => SpoolError::Reserved { found: 1 },
                _ => SpoolError::StreamEpoch,
            };
            match failure(&b) {
                Error::Spool(e) => assert_eq!(e, expected),
                _ => panic!("wrong error"),
            }
        }
        let mut b = segment(header(0), &[b" "]);
        append(&mut b, 2, b"x");
        assert!(matches!(
            failure(&b),
            Error::Spool(SpoolError::Sequence {
                expected: Some(1),
                found: 2,
                ..
            })
        ));
        let mut b = segment(header(0), &[]);
        b.extend_from_slice(&1_048_577u32.to_le_bytes());
        assert!(matches!(
            failure(&b),
            Error::Spool(SpoolError::PayloadTooLarge { length: 1_048_577 })
        ));
    }
    #[test]
    fn rejects_tail() {
        for count in [0, 1] {
            let payloads: Vec<&[u8]> = vec![b"x"; count];
            let base = segment(header(0), &payloads);
            for suffix in 1..17 {
                let mut b = base.clone();
                b.extend(vec![0; suffix]);
                if suffix == 16 {
                    b[base.len() + 8] = 2;
                }
                let kind = if suffix < 16 {
                    TailKind::Incomplete
                } else {
                    TailKind::Checksum
                };
                assert!(
                    matches!(failure(&b), Error::Tail(t) if t.offset == base.len() && t.kind == kind)
                );
            }
        }
        let mut b = segment(header(0), &[b"x", b"y"]);
        b[49 + 8] = 3;
        assert!(matches!(failure(&b), Error::Tail(t) if t.kind == TailKind::Checksum));
    }
    #[test]
    fn rejects_empty_and_count() {
        assert!(matches!(failure(&segment(header(0), &[])), Error::Empty));
        let b = segment(header(0), &vec![b"".as_slice(); 5001]);
        assert!(matches!(failure(&b), Error::RecordCount { count: 5001 }));
        for n in [1, 4999, 5000] {
            assert!(prepare(&segment(header(0), &vec![b"x".as_slice(); n])).is_ok());
        }
    }
    #[test]
    fn line_framing_precedence() {
        for (p, kind) in [
            (b"".as_slice(), LineFraming::Blank),
            (b" \t", LineFraming::Blank),
            (b"\xef\xbb\xbf\n", LineFraming::Bom),
            (b"x\r\n", LineFraming::Lf),
            (b"x\r", LineFraming::Cr),
        ] {
            for index in [0, 1] {
                let mut ps = vec![b"x".as_slice(); index];
                ps.push(p);
                assert!(
                    matches!(failure(&segment(header(0), &ps)), Error::LineFraming { index: i, kind: k } if i == index && k == kind)
                );
            }
        }
    }
    #[test]
    fn decoded_limit_precedence() {
        let p = vec![b'x'; 1_048_576];
        for delta in [0, 1, 2] {
            let last = vec![b'x'; 1_048_572 + delta];
            let b = segment(header(0), &[&p, &p, &p, &last]);
            if delta == 0 {
                assert!(prepare(&b).is_ok());
            } else {
                assert!(matches!(failure(&b), Error::DecodedLimit { index: 3 }));
            }
        }
        let mut last = vec![b'x'; 1_048_573];
        last[0] = b'\r';
        assert!(matches!(
            failure(&segment(header(0), &[&p, &p, &p, &last])),
            Error::LineFraming { index: 3, .. }
        ));
        last[0] = b'x';
        assert!(matches!(
            failure(&segment(header(0), &[&p, &p, &p, &last, b"\n"])),
            Error::DecodedLimit { index: 3 }
        ));
    }
    #[test]
    fn descriptors_all_classes() {
        for class in [
            SpoolClass::Raw,
            SpoolClass::Context,
            SpoolClass::Lineage,
            SpoolClass::Findings,
            SpoolClass::Audit,
        ] {
            let h = Header {
                class,
                stream_epoch: u64::MAX,
                segment_id: u64::MAX,
                first_sequence: 0,
            };
            let b = segment(h, &[b"x", b"y"]);
            let p = prepare(&b).unwrap();
            assert_eq!(
                p.header,
                format!(
                    "v=1;class={};epoch={};segment={};first=0;last=1;count=2",
                    class.as_str(),
                    u64::MAX,
                    u64::MAX
                )
            );
            assert_eq!(
                &p.descriptor[..12],
                &[0x50, 0x2a, 0x4d, 0x18, 40, 0, 0, 0, 1, class as u8, 0, 0]
            );
            assert_eq!(&p.descriptor[12..28], &[255; 16]);
            assert_eq!(&p.descriptor[28..36], &[0; 8]);
            assert_eq!(&p.descriptor[36..44], &1u64.to_le_bytes());
            assert_eq!(&p.descriptor[44..], &2u32.to_le_bytes());
            assert_eq!(p.plain, b"x\ny\n");
        }
    }
    #[test]
    fn sequence_boundaries() {
        for (first, count) in [(0, 1), (u64::MAX, 1), (u64::MAX - 1, 2)] {
            assert!(prepare(&segment(header(first), &vec![b"x".as_slice(); count])).is_ok());
        }
        let mut b = segment(header(u64::MAX), &[b"x"]);
        append(&mut b, 0, b"y");
        let e = failure(&b);
        assert!(std::error::Error::source(&e).is_some());
        assert!(matches!(
            e,
            Error::Spool(SpoolError::Sequence {
                expected: None,
                found: 0,
                ..
            })
        ));
    }
}
