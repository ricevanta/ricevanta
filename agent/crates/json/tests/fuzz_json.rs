//! Fixed-budget mutation properties on stable Rust, not coverage-guided fuzzing.
//!
//! Seeds are the shared vectors. Each case applies one mutation (byte flip,
//! truncation, duplication of a slice, depth growth, insertion or removal) and
//! requires that the reader terminates without panicking and that every
//! accepted mutant re-encodes to bytes that parse to an equal `Value`, whose
//! encoding is a fixed point.

#[path = "support/oracle.rs"]
mod oracle;

use ricevanta_json::{MAX_INPUT_BYTES, encode, parse};
use std::time::Instant;

const SEED: u64 = 0x52564a534f4e5631;
const VECTORS: &[u8] = include_bytes!("../../../../schemas/agent/json/v1/vectors.json");

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

const ALPHABET: &[u8] =
    b"{}[]\",:\\ 0123456789-.eEtrufalsn\x00\x1f\x7f\xc3\xa9\xef\xbb\xbf\xed\xa0\x80u";

fn seeds() -> Vec<Vec<u8>> {
    let root = oracle::parse(VECTORS);
    let mut seeds: Vec<Vec<u8>> = root
        .get("cases")
        .items()
        .iter()
        .map(|case| oracle::hex(case.get("input_hex").str()))
        .collect();
    seeds.push(br#"{"a":{"b":[1,-2,"\u00e9",true,null,{"c":"\ud83d\ude00"}]}}"#.to_vec());
    seeds
}

fn mutate(bytes: &mut Vec<u8>, random: &mut Random, operation: usize) {
    match operation {
        0 if !bytes.is_empty() => {
            let index = random.index(bytes.len());
            bytes[index] ^= 1 << random.index(8);
        }
        1 => {
            let cut = random.index(bytes.len() + 1);
            bytes.truncate(cut);
        }
        2 if !bytes.is_empty() => {
            let start = random.index(bytes.len());
            let end = start + random.index(bytes.len() - start) + 1;
            let slice = bytes[start..end].to_vec();
            let at = random.index(bytes.len() + 1);
            bytes.splice(at..at, slice);
        }
        3 => {
            let levels = 1 + random.index(10);
            let mut grown = Vec::with_capacity(bytes.len() + 2 * levels);
            let open: Vec<u8> = (0..levels)
                .map(|_| if random.next() & 1 == 0 { b'[' } else { b'{' })
                .collect();
            for &b in &open {
                grown.push(b);
                if b == b'{' {
                    grown.extend_from_slice(b"\"k\":");
                }
            }
            grown.extend_from_slice(bytes);
            for &b in open.iter().rev() {
                grown.push(if b == b'[' { b']' } else { b'}' });
            }
            *bytes = grown;
        }
        4 => {
            let at = random.index(bytes.len() + 1);
            bytes.insert(at, ALPHABET[random.index(ALPHABET.len())]);
        }
        5 if !bytes.is_empty() => {
            let at = random.index(bytes.len());
            bytes.remove(at);
        }
        _ => {
            let at = random.index(bytes.len() + 1);
            bytes.insert(at, random.next() as u8);
        }
    }
}

fn run_case<T>(context: &str, action: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(action)) {
        Ok(value) => value,
        Err(_) => panic!("{context}: case panicked"),
    }
}

fn check(input: &[u8], context: &str) -> bool {
    match parse(input) {
        Ok(value) => {
            assert!(
                input.len() <= MAX_INPUT_BYTES,
                "{context}: oversized input accepted"
            );
            let encoded = encode(&value);
            let again = parse(encoded.as_bytes())
                .unwrap_or_else(|e| panic!("{context}: canonical form rejected: {e:?}"));
            assert_eq!(again, value, "{context}: re-parse differs");
            assert_eq!(
                encode(&again),
                encoded,
                "{context}: encoding not a fixed point"
            );
            true
        }
        Err(error) => {
            assert!(
                error.offset() <= input.len().max(MAX_INPUT_BYTES),
                "{context}: offset"
            );
            false
        }
    }
}

fn run(budget: usize) {
    let start = Instant::now();
    let mut random = Random(SEED);
    let seeds = seeds();
    let mut corpus = seeds.clone();
    let mut accepted = 0usize;
    for case in 0..budget {
        let context = format!("seed={SEED:#018x} case={case}");
        run_case(&context, || {
            // Alternate between fresh seeds and accumulated mutants so
            // mutations compound, bounded so inputs stay near the limit.
            let mut input = if case % 3 == 0 {
                seeds[random.index(seeds.len())].clone()
            } else {
                corpus[random.index(corpus.len())].clone()
            };
            let operations = 1 + random.index(3);
            for _ in 0..operations {
                let operation = random.index(7);
                mutate(&mut input, &mut random, operation);
            }
            if check(&input, &context) {
                accepted += 1;
            }
            if input.len() <= 2 * MAX_INPUT_BYTES && corpus.len() < 512 {
                corpus.push(input);
            } else if input.len() <= 2 * MAX_INPUT_BYTES {
                let slot = random.index(corpus.len());
                corpus[slot] = input;
            }
        });
    }
    let elapsed = start.elapsed();
    eprintln!("seed={SEED:#018x} cases={budget} accepted={accepted} elapsed={elapsed:?}");
    assert!(
        accepted > 0,
        "no mutant was accepted; the property is vacuous"
    );
}

#[test]
fn fuzz_json() {
    run(2_000);
}

#[test]
#[ignore = "extended 20,000-case budget; CI json-extended"]
fn fuzz_json_extended() {
    run(20_000);
}

#[test]
fn panic_wrapper_reports_seed_and_case() {
    let context = format!("seed={SEED:#018x} case=7");
    let failure = std::panic::catch_unwind(|| {
        run_case(&context, || panic!("injected helper failure"));
    })
    .unwrap_err();
    let diagnostic = failure.downcast_ref::<String>().unwrap();
    assert_eq!(diagnostic, &format!("{context}: case panicked"));
}
