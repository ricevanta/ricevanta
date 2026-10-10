//! File-free v1 spool encoding and borrowed recovery.
//!
//! Integers use explicit little-endian fields. Checksums detect corruption,
//! not authenticity. This crate provides no storage or durability guarantees.

use std::fmt;

/// Supported segment format version.
pub const FORMAT_VERSION: u16 = 1;
/// Encoded segment header size in bytes.
pub const HEADER_LEN: usize = 32;
/// Encoded record framing size, excluding payload.
pub const RECORD_HEADER_LEN: usize = 16;
/// Maximum opaque payload size in bytes.
pub const MAX_PAYLOAD_LEN: usize = 1_048_576;

/// Independent event stream class, matching the Go batch descriptor values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SpoolClass {
    /// Raw events.
    Raw = 1,
    /// Context events.
    Context = 2,
    /// Lineage events.
    Lineage = 3,
    /// Findings.
    Findings = 4,
    /// Audit events.
    Audit = 5,
}

impl TryFrom<u8> for SpoolClass {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Raw),
            2 => Ok(Self::Context),
            3 => Ok(Self::Lineage),
            4 => Ok(Self::Findings),
            5 => Ok(Self::Audit),
            found => Err(Error::Class { found }),
        }
    }
}

impl SpoolClass {
    /// Returns the canonical class name shared with Go.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Context => "context",
            Self::Lineage => "lineage",
            Self::Findings => "findings",
            Self::Audit => "audit",
        }
    }
}

/// Segment identity and initial per-class sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Independent event class.
    pub class: SpoolClass,
    /// Nonzero stream namespace; creation and persistence belong to the caller.
    pub stream_epoch: u64,
    /// Segment counter; zero is legal.
    pub segment_id: u64,
    /// Expected sequence of the first record; zero is legal.
    pub first_sequence: u64,
}

/// Fatal framing errors and encoder preflight errors.
///
/// Recovery checks header size, magic, version, class, reserved byte and epoch
/// in that order. Record length precedes completeness, CRC and sequence checks.
/// Errors never mutate input or output and never return a recovered prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Input lacks a complete segment header.
    HeaderTooShort {
        /// Supplied input length.
        actual: usize,
    },
    /// Header magic differs from `RVSP`.
    Magic,
    /// Header version is unsupported.
    Version {
        /// Stored version.
        found: u16,
    },
    /// Header class is unknown.
    Class {
        /// Stored class byte.
        found: u8,
    },
    /// Header reserved byte is nonzero.
    Reserved {
        /// Stored reserved byte.
        found: u8,
    },
    /// Stream epoch is zero.
    StreamEpoch,
    /// Payload length exceeds the format ceiling.
    PayloadTooLarge {
        /// Supplied or stored payload length.
        length: usize,
    },
    /// Encoder scratch buffer is too short.
    OutputTooSmall {
        /// Required encoded size.
        needed: usize,
        /// Supplied output length.
        actual: usize,
    },
    /// Checksum-valid record breaks sequence continuity.
    Sequence {
        /// Record start in the original input.
        offset: usize,
        /// Required sequence; `None` means the stream is exhausted.
        expected: Option<u64>,
        /// Stored sequence.
        found: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderTooShort { actual } => {
                write!(f, "header requires {HEADER_LEN} bytes, got {actual}")
            }
            Self::Magic => f.write_str("invalid spool magic"),
            Self::Version { found } => write!(f, "unsupported spool version {found}"),
            Self::Class { found } => write!(f, "unknown spool class {found}"),
            Self::Reserved { found } => write!(f, "nonzero reserved byte {found}"),
            Self::StreamEpoch => f.write_str("stream epoch must be nonzero"),
            Self::PayloadTooLarge { length } => {
                write!(f, "payload length {length} exceeds {MAX_PAYLOAD_LEN}")
            }
            Self::OutputTooSmall { needed, actual } => {
                write!(f, "output requires {needed} bytes, got {actual}")
            }
            Self::Sequence {
                offset,
                expected,
                found,
            } => write!(
                f,
                "sequence at offset {offset}: expected {expected:?}, got {found}"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// Encodes canonical v1 header bytes, rejecting a zero stream epoch.
///
/// Zero segment and sequence counters and all nonzero u64 epochs are accepted.
/// The returned array belongs to the caller; no allocation or I/O occurs.
pub fn encode_header(header: Header) -> Result<[u8; HEADER_LEN], Error> {
    if header.stream_epoch == 0 {
        return Err(Error::StreamEpoch);
    }
    let mut bytes = [0; HEADER_LEN];
    bytes[..4].copy_from_slice(b"RVSP");
    bytes[4..6].copy_from_slice(&FORMAT_VERSION.to_le_bytes());
    bytes[6] = header.class as u8;
    bytes[8..16].copy_from_slice(&header.stream_epoch.to_le_bytes());
    bytes[16..24].copy_from_slice(&header.segment_id.to_le_bytes());
    bytes[24..32].copy_from_slice(&header.first_sequence.to_le_bytes());
    Ok(bytes)
}

/// A sequence and opaque payload borrowed from caller-owned bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    /// Per-class sequence; zero and u64::MAX are legal.
    pub sequence: u64,
    /// Exact opaque bytes; empty and non-JSON payloads are legal framing.
    pub payload: &'a [u8],
}

/// Encodes one record into caller-owned scratch space without allocating.
///
/// Oversized payloads take precedence over short output. Either error preserves
/// the entire output. Success returns `16 + payload.len()` and preserves trailing
/// bytes. Sequence continuity belongs to segment recovery, not this encoder.
pub fn encode_record(record: Record<'_>, output: &mut [u8]) -> Result<usize, Error> {
    let length = record.payload.len();
    if length > MAX_PAYLOAD_LEN {
        return Err(Error::PayloadTooLarge { length });
    }
    // The payload cap bounds both the addition and conversion to u32.
    let needed = RECORD_HEADER_LEN + length;
    if output.len() < needed {
        return Err(Error::OutputTooSmall {
            needed,
            actual: output.len(),
        });
    }
    let sequence = record.sequence.to_le_bytes();
    let checksum = crc32c::crc32c_append(crc32c::crc32c(&sequence), record.payload);
    output[..4].copy_from_slice(&(length as u32).to_le_bytes());
    output[4..8].copy_from_slice(&checksum.to_le_bytes());
    output[8..16].copy_from_slice(&sequence);
    output[16..needed].copy_from_slice(record.payload);
    Ok(needed)
}

/// Repairable suffix classification; neither kind establishes durable truncation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TailKind {
    /// A length field, framing field or payload is incomplete.
    Incomplete,
    /// A complete record has an incorrect checksum.
    Checksum,
}

/// First rejected record boundary; the entire suffix is excluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TailIssue {
    /// Original input offset, equal to the recovered valid length.
    pub offset: usize,
    /// Reason the suffix was rejected.
    pub kind: TailKind,
}

/// Immutable validated prefix and constant-size recovery summary.
///
/// Payloads borrow the original input. Private bounds prevent access to rejected
/// suffix bytes. Recovery and iteration allocate no records or payload buffers.
#[derive(Debug)]
pub struct Recovery<'a> {
    prefix: &'a [u8],
    header: Header,
    record_count: usize,
    next_sequence: Option<u64>,
    tail: Option<TailIssue>,
}

impl<'a> Recovery<'a> {
    /// Returns the validated segment identity.
    pub fn header(&self) -> Header {
        self.header
    }

    /// Returns the accepted byte count, including the 32-byte header.
    pub fn valid_len(&self) -> usize {
        self.prefix.len()
    }

    /// Returns the number of complete, checksum-valid contiguous records.
    pub fn record_count(&self) -> usize {
        self.record_count
    }

    /// Returns the sequence required at the accepted prefix boundary.
    ///
    /// `None` means a record at u64::MAX exhausted the stream, not sequence zero.
    pub fn next_sequence(&self) -> Option<u64> {
        self.next_sequence
    }

    /// Returns the first repairable suffix defect, or `None` for clean EOF.
    pub fn tail(&self) -> Option<TailIssue> {
        self.tail
    }

    /// Iterates in stored order over the validated prefix without CRC rescans.
    ///
    /// Repeated calls yield identical records. Payload lifetimes follow the
    /// original input, so the iterator may outlive this summary.
    pub fn records(&self) -> impl Iterator<Item = Record<'a>> + 'a {
        let mut remaining = &self.prefix[HEADER_LEN..];
        std::iter::from_fn(move || {
            if remaining.is_empty() {
                return None;
            }
            // Only recover constructs this prefix, with all lengths validated.
            let length = read_u32(remaining) as usize;
            let needed = RECORD_HEADER_LEN + length;
            let record = Record {
                sequence: read_u64(&remaining[8..16]),
                payload: &remaining[RECORD_HEADER_LEN..needed],
            };
            remaining = &remaining[needed..];
            Some(record)
        })
    }
}

// Callers establish fixed-field completeness before these explicit endian reads.
fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

/// Recovers a borrowed contiguous prefix, leaving the entire input unchanged.
///
/// Header checks run in size, magic, version, class, reserved and epoch order.
/// Record checks run in length, completeness, CRC and sequence order. Incomplete
/// or bad-CRC records stop scanning and exclude the entire suffix. Unsupported
/// headers, oversized lengths and checksum-valid sequence errors return no
/// prefix. There is no segment-byte or record-count ceiling and no file I/O,
/// allocation, authenticity check or durability guarantee.
pub fn recover(input: &[u8]) -> Result<Recovery<'_>, Error> {
    if input.len() < HEADER_LEN {
        return Err(Error::HeaderTooShort {
            actual: input.len(),
        });
    }
    if &input[..4] != b"RVSP" {
        return Err(Error::Magic);
    }
    let version = u16::from_le_bytes([input[4], input[5]]);
    if version != FORMAT_VERSION {
        return Err(Error::Version { found: version });
    }
    let class = SpoolClass::try_from(input[6])?;
    if input[7] != 0 {
        return Err(Error::Reserved { found: input[7] });
    }
    let stream_epoch = read_u64(&input[8..16]);
    if stream_epoch == 0 {
        return Err(Error::StreamEpoch);
    }
    let header = Header {
        class,
        stream_epoch,
        segment_id: read_u64(&input[16..24]),
        first_sequence: read_u64(&input[24..32]),
    };
    let mut offset = HEADER_LEN;
    let mut record_count = 0;
    let mut expected = Some(header.first_sequence);
    let tail = loop {
        let remaining = &input[offset..];
        if remaining.is_empty() {
            break None;
        }
        if remaining.len() < 4 {
            break Some(TailIssue {
                offset,
                kind: TailKind::Incomplete,
            });
        }
        let length = read_u32(remaining) as usize;
        if length > MAX_PAYLOAD_LEN {
            return Err(Error::PayloadTooLarge { length });
        }
        // The payload cap bounds needed. Compare remaining bytes before adding
        // any offset, so even a full-width hostile length cannot overflow.
        let needed = RECORD_HEADER_LEN + length;
        if remaining.len() < needed {
            break Some(TailIssue {
                offset,
                kind: TailKind::Incomplete,
            });
        }
        let stored = read_u32(&remaining[4..8]);
        let checksum = crc32c::crc32c(&remaining[8..needed]);
        if checksum != stored {
            break Some(TailIssue {
                offset,
                kind: TailKind::Checksum,
            });
        }
        let sequence = read_u64(&remaining[8..16]);
        if expected != Some(sequence) {
            return Err(Error::Sequence {
                offset,
                expected,
                found: sequence,
            });
        }
        // needed <= input.len() - offset proves the addition fits. Each accepted
        // record consumes at least 16 bytes, bounding the count below usize::MAX.
        offset += needed;
        record_count += 1;
        expected = sequence.checked_add(1);
    };
    Ok(Recovery {
        prefix: &input[..offset],
        header,
        record_count,
        next_sequence: expected,
        tail,
    })
}
