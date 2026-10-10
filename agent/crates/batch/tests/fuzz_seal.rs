//! Stable deterministic bounded mutation tests. No fuzz runtime dependency.
mod support;
use ricevanta_batch::seal;
use support::*;

const SEED: u64 = 0x5249564241544348;
fn run(cases: usize) {
    let start = std::time::Instant::now();
    for input in mutation_cases(SEED, cases) {
        assert!(input.len() <= 65_536);
        let original = input.clone();
        let first = std::panic::catch_unwind(|| seal(&input)).unwrap();
        let second = std::panic::catch_unwind(|| seal(&input)).unwrap();
        assert_eq!(input, original);
        match (first, second) {
            (Err(a), Err(b)) => {
                assert_eq!(std::mem::discriminant(&a), std::mem::discriminant(&b));
                assert_eq!(format!("{a:?}"), format!("{b:?}"));
            }
            (Ok(a), Ok(b)) => {
                assert_eq!(a.header_value(), b.header_value());
                let mut ps = Vec::new();
                let mut pos = 32;
                let mut last = 0;
                while pos < input.len() {
                    let len = u32::from_le_bytes(input[pos..pos + 4].try_into().unwrap()) as usize;
                    last = u64::from_le_bytes(input[pos + 8..pos + 16].try_into().unwrap());
                    let end = pos + 16 + len;
                    ps.push(&input[pos + 16..end]);
                    pos = end;
                }
                let expected = plain(&ps);
                inspect(a.body(), expected.len());
                assert_eq!(
                    zstd::bulk::decompress(&a.body()[48..], expected.len()).unwrap(),
                    expected
                );
                assert_eq!(
                    zstd::bulk::decompress(&b.body()[48..], expected.len()).unwrap(),
                    expected
                );
                let epoch = u64::from_le_bytes(input[8..16].try_into().unwrap());
                let segment = u64::from_le_bytes(input[16..24].try_into().unwrap());
                let first = u64::from_le_bytes(input[24..32].try_into().unwrap());
                let class = ricevanta_spool::SpoolClass::try_from(input[6]).unwrap();
                assert_eq!(
                    a.header_value(),
                    format!(
                        "v=1;class={};epoch={epoch};segment={segment};first={first};last={last};count={}",
                        class.as_str(),
                        ps.len()
                    )
                );
                assert_eq!(
                    &a.body()[..12],
                    &[0x50, 0x2a, 0x4d, 0x18, 40, 0, 0, 0, 1, input[6], 0, 0]
                );
                for (offset, value) in [(12, epoch), (20, segment), (28, first), (36, last)] {
                    assert_eq!(&a.body()[offset..offset + 8], &value.to_le_bytes());
                }
                assert_eq!(&a.body()[44..48], &(ps.len() as u32).to_le_bytes());
            }
            _ => panic!("nonrepeatable result"),
        }
    }
    eprintln!(
        "seed=0x{SEED:016x} cases={cases} elapsed={:?}",
        start.elapsed()
    );
}
#[test]
fn fuzz_seal() {
    run(2_000)
}
#[test]
#[ignore = "extended deterministic qualification; run separately"]
fn fuzz_seal_extended() {
    run(20_000)
}
#[test]
fn fixed_boundary_seeds() {
    for first in [0, u64::MAX] {
        verify(header(first), &[b"x"]);
    }
    for size in [255, 256, 65_791, 65_792, 1_048_576, 1_048_577] {
        verify(header(0), &[&vec![b'x'; size - 1]]);
    }
    for count in [1, 4999, 5000] {
        verify(header(0), &vec![b"x".as_slice(); count]);
    }
    let p = vec![b'x'; 1_048_575];
    verify(header(0), &[&p, &p, &p, &p]);
    assert!(seal(&segment(header(0), &vec![b"x".as_slice(); 5001])).is_err());
    assert!(seal(&vec![0; 4_269_336]).is_err());
    assert!(seal(&vec![0; 4_269_337]).is_err());
}
