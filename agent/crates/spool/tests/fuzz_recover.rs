//! Fixed-budget mutation properties on stable Rust, not coverage-guided fuzzing.

mod support;
use ricevanta_spool::{Header, Record, SpoolClass, encode_header, encode_record, recover};
use std::time::Instant;

const SEED: u64 = 0x525653505f763031;
const LENGTHS: [u32; 11] = [0, 1, 3, 4, 15, 16, 31, 32, 33, 1_048_576, u32::MAX];

// xorshift64: u64 XOR with left 13, right 7, left 17, in that order.
struct Random(u64);
impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn index(&mut self, limit: usize) -> usize {
        (self.next() % limit as u64) as usize
    }
}

fn generated_round_trip(random: &mut Random, case: usize, context: &str) -> Vec<u8> {
    let first_sequence = match case % 64 {
        0 => u64::MAX,
        1 => 0,
        _ => random.next() & !3,
    };
    let header = Header {
        class: SpoolClass::try_from(1 + random.index(5) as u8).unwrap(),
        stream_epoch: random.next() | 1,
        segment_id: random.next(),
        first_sequence,
    };
    let mut bytes = encode_header(header).unwrap().to_vec();
    assert_eq!(
        &bytes[..8],
        &[b'R', b'V', b'S', b'P', 1, 0, header.class as u8, 0],
        "{context}: header bytes"
    );
    assert_eq!(
        &bytes[8..16],
        &header.stream_epoch.to_le_bytes(),
        "{context}: epoch bytes"
    );
    assert_eq!(
        &bytes[16..24],
        &header.segment_id.to_le_bytes(),
        "{context}: segment bytes"
    );
    assert_eq!(
        &bytes[24..32],
        &header.first_sequence.to_le_bytes(),
        "{context}: first sequence bytes"
    );
    let count = if first_sequence == u64::MAX { 1 } else { 3 };
    let mut payloads = Vec::new();
    for index in 0..count {
        let length = random.index(257);
        let payload: Vec<_> = (0..length).map(|_| random.next() as u8).collect();
        let sequence = first_sequence + index as u64;
        let mut encoded = vec![0xa5; 16 + payload.len() + 3];
        let length = encode_record(
            Record {
                sequence,
                payload: &payload,
            },
            &mut encoded,
        )
        .unwrap();
        assert_eq!(length, 16 + payload.len(), "{context}: encoded length");
        assert_eq!(
            &encoded[..4],
            &(payload.len() as u32).to_le_bytes(),
            "{context}: length bytes"
        );
        assert_eq!(
            &encoded[4..8],
            &support::crc(&[&sequence.to_le_bytes(), &payload]).to_le_bytes(),
            "{context}: encoded CRC"
        );
        assert_eq!(
            &encoded[8..16],
            &sequence.to_le_bytes(),
            "{context}: sequence bytes"
        );
        assert!(encoded[16..length] == payload, "{context}: encoded payload");
        assert_eq!(&encoded[length..], &[0xa5; 3], "{context}: trailing bytes");
        bytes.extend_from_slice(&encoded[..length]);
        payloads.push(payload);
    }
    let recovered =
        recover(&bytes).unwrap_or_else(|e| panic!("{context}: generated round trip: {e:?}"));
    assert_eq!(recovered.header(), header, "{context}: header round trip");
    assert_eq!(
        recovered.valid_len(),
        bytes.len(),
        "{context}: full round trip"
    );
    assert_eq!(recovered.tail(), None, "{context}: round trip tail");
    assert_eq!(
        recovered.record_count(),
        count,
        "{context}: round trip count"
    );
    assert_eq!(
        recovered.next_sequence(),
        (first_sequence + (count - 1) as u64).checked_add(1),
        "{context}: round trip summary"
    );
    for (index, (record, payload)) in recovered.records().zip(&payloads).enumerate() {
        assert_eq!(
            record.sequence,
            first_sequence + index as u64,
            "{context}: round trip sequence"
        );
        assert!(record.payload == payload, "{context}: round trip payload");
    }
    bytes
}

fn mutate(bytes: &mut Vec<u8>, random: &mut Random, operation: usize, round: usize) {
    match operation {
        0 => {
            let cut = random.index(bytes.len() + 1);
            bytes.truncate(cut);
        }
        1 if !bytes.is_empty() => {
            let index = random.index(bytes.len());
            bytes[index] ^= 1 << random.index(8);
        }
        2 if bytes.len() < 8192 => {
            let index = random.index(bytes.len() + 1);
            bytes.insert(index, random.next() as u8);
        }
        3 if !bytes.is_empty() => {
            let index = random.index(bytes.len());
            bytes.remove(index);
        }
        4 => {
            if bytes.len() < 36 {
                *bytes = support::segment(0, &[(0, b"seed")]);
            }
            let length = LENGTHS[round % LENGTHS.len()];
            bytes[32..36].copy_from_slice(&length.to_le_bytes());
        }
        5 => {
            if bytes.len() < 48 {
                *bytes = support::segment(0, &[(0, b"seed")]);
            }
            let sequence = [0, 1, u64::MAX, random.next()][round % 4];
            bytes[40..48].copy_from_slice(&sequence.to_le_bytes());
            // Half the substitutions retain a stale CRC. The other half isolate
            // sequence enforcement using the independent checksum oracle.
            if round.is_multiple_of(2) {
                let length = u32::from_le_bytes(bytes[32..36].try_into().unwrap()) as usize;
                if length <= bytes.len() - 48 {
                    let checksum = support::crc(&[&bytes[40..48 + length]]);
                    bytes[36..40].copy_from_slice(&checksum.to_le_bytes());
                }
            }
        }
        _ => {
            let length = round % 4097;
            *bytes = (0..length).map(|_| random.next() as u8).collect();
        }
    }
    assert!(bytes.len() <= 8192);
}

// Catch the whole case, including encoders and iterators, so failures always
// identify the deterministic input without formatting a panic payload.
fn run_case<T>(context: &str, action: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
        Ok(value) => value,
        Err(_) => panic!("{context}: case panicked"),
    }
}

fn run_cases(budget: usize) {
    let start = Instant::now();
    let mut random = Random(SEED);
    let mut seeds: Vec<Vec<u8>> = support::fixture_data::FIXTURES
        .iter()
        .map(|f| f.input.to_vec())
        .collect();
    for (case, seed) in seeds.iter().enumerate() {
        let context = format!("seed={SEED:#018x} case={case} shared fixture");
        run_case(&context, || {
            support::check_recovery_invariants(seed, &context)
        });
    }
    for case in 0..32 {
        let context = format!("seed={SEED:#018x} case={case} generated seed");
        seeds.push(run_case(&context, || {
            generated_round_trip(&mut random, case, &context)
        }));
    }
    for case in 0..budget {
        let context = format!("seed={SEED:#018x} case={case}");
        run_case(&context, || {
            let round_trip = generated_round_trip(&mut random, case, &context);
            support::check_recovery_invariants(&round_trip, &context);
            let mut mutation = seeds[(case / 7) % seeds.len()].clone();
            mutate(&mut mutation, &mut random, case % 7, case / 7);
            support::check_recovery_invariants(&mutation, &context);
            // Enumerate every length 0..=4096 in each normal budget, independently
            // of the mutation cycle's seed and operation choices.
            let arbitrary: Vec<_> = (0..case % 4097).map(|_| random.next() as u8).collect();
            support::check_recovery_invariants(&arbitrary, &context);
        });
    }
    eprintln!(
        "seed={SEED:#018x} cases={budget} elapsed={:?}",
        start.elapsed()
    );
}

#[test]
fn fuzz_recover() {
    run_cases(10_000);
}

#[test]
#[ignore = "extended 100,000-case budget required before review"]
fn fuzz_recover_extended() {
    run_cases(100_000);
}

#[test]
fn panic_wrapper_reports_seed_and_case() {
    let context = format!("seed={SEED:#018x} case=123");
    let failure = std::panic::catch_unwind(|| {
        run_case(&context, || panic!("injected helper failure"));
    })
    .unwrap_err();
    let diagnostic = failure.downcast_ref::<String>().unwrap();
    assert_eq!(diagnostic, &format!("{context}: case panicked"));
    assert!(!diagnostic.contains("injected helper failure"));
    assert_eq!(run_case(&context, || 7), 7);
}
