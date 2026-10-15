const SEED: u64 = 0x5249564241544348;
#[test]
fn ordinary() { assert_eq!(tiny::add(1, 2), 3); }
#[test]
#[ignore = "extended"]
fn props_extended() {
    let start = std::time::Instant::now();
    let cases = 20_000usize;
    for i in 0..cases { assert_eq!(tiny::add(i as u32, 1), i as u32 + 1); }
    eprintln!("seed=0x{SEED:016x} cases={cases} elapsed={:?}", start.elapsed());
}
