//! Completed output, frame profile and ownership checks.
mod support;
use ricevanta_batch::{Error, MAX_NDJSON_BYTES, seal};
use support::*;

#[test]
fn seals_one_frame() {
    verify(header(0), &[b"x"]);
    verify(header(u64::MAX), &[b"x"]);
    verify(header(u64::MAX - 1), &[b"x", b"y"]);
}
#[test]
fn content_size_boundaries() {
    for size in [255, 256, 65_791, 65_792] {
        verify(header(0), &[&vec![b'x'; size - 1]]);
    }
}
#[test]
fn max_ndjson() {
    let mut remaining = MAX_NDJSON_BYTES;
    let payloads: Vec<Vec<u8>> = (0..5000)
        .map(|i| {
            let line = remaining / (5000 - i);
            remaining -= line;
            vec![b'x'; line - 1]
        })
        .collect();
    let slices: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
    let input = segment(header(0), &slices);
    assert_eq!(input.len(), ricevanta_batch::MAX_SEGMENT_BYTES);
    verify(header(0), &slices);

    let p = vec![b'x'; 1_048_576];
    for total in [MAX_NDJSON_BYTES - 1, MAX_NDJSON_BYTES] {
        let last = vec![b'x'; total - 3 * (p.len() + 1) - 1];
        verify(header(0), &[&p, &p, &p, &last]);
    }
    let last = vec![b'x'; 1_048_573];
    assert!(matches!(
        seal(&segment(header(0), &[&p, &p, &p, &last])),
        Err(Error::DecodedLimit { index: 3 })
    ));
    for size in [1_048_575, 1_048_576] {
        verify(header(0), &[&vec![b'x'; size]]);
    }
    assert!(matches!(
        seal(&segment(header(0), &[&vec![b'x'; 1_048_577]])),
        Err(Error::Spool(ricevanta_spool::Error::PayloadTooLarge { .. }))
    ));
}
#[test]
fn max_records() {
    for n in [4999, 5000] {
        verify(header(0), &vec![b"x".as_slice(); n]);
    }
}
#[test]
fn incompressible_bound() {
    let n = MAX_NDJSON_BYTES;
    let independent = n + (n >> 8) + if n < 131_072 { (131_072 - n) >> 11 } else { 0 };
    assert_eq!(zstd::zstd_safe::compress_bound(n), independent);
    assert_eq!(48 + independent, 4_210_736);
    let mut state = 0x5249564241544348u64;
    let mut bytes = Vec::with_capacity(n - 4);
    for _ in 0..n - 4 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let mut b = state as u8;
        if matches!(b, 10 | 13) {
            b = 0;
        }
        bytes.push(b);
    }
    let ps: Vec<&[u8]> = bytes.chunks(1_048_575).collect();
    let out = verify(header(0), &ps);
    assert!(out.body().len() <= 4_210_736);
}
#[test]
fn preserves_payload_bytes() {
    verify(
        header(0),
        &[
            b"x \\n\\r\t",
            "é".as_bytes(),
            &[0xff, 0xfe],
            b"x\xef\xbb\xbf",
        ],
    );
}
#[test]
fn quarantine_payloads_seal() {
    verify(
        header(0),
        &[
            b"not JSON",
            b"{}",
            b"{\"metadata\":{\"sequence\":999}}",
            &[0xff],
        ],
    );
}
#[test]
fn owned_output() {
    let out = {
        let input = segment(header(0), &[b"x"]);
        seal(&input).unwrap()
    };
    let (h, b) = out.into_parts();
    assert_eq!(h, "v=1;class=raw;epoch=1;segment=0;first=0;last=0;count=1");
    inspect(&b, 2);
}
#[test]
fn redacts_debug() {
    let out = verify(header(0), &[b"sensitive-payload-marker"]);
    let s = format!("{out:?}");
    assert!(!s.contains("sensitive"));
    assert!(!s.contains("class="));
    assert!(s.contains("body_len"));
}
#[test]
fn compression_error_source() {
    let e = Error::Compression(std::io::Error::other("codec marker"));
    assert!(
        std::error::Error::source(&e)
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .is_some()
    );
    assert!(!e.to_string().contains("marker"));
}
