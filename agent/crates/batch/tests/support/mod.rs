#![allow(dead_code)] // Shared by integration targets with different assertion needs.
use ricevanta_spool::{Header, SpoolClass};

pub fn header(first: u64) -> Header {
    Header {
        class: SpoolClass::Raw,
        stream_epoch: 1,
        segment_id: 0,
        first_sequence: first,
    }
}
pub fn crc(bytes: &[u8]) -> u32 {
    let mut c = !0u32;
    for b in bytes {
        c ^= u32::from(*b);
        for _ in 0..8 {
            c = (c >> 1) ^ (0x82f63b78 & 0u32.wrapping_sub(c & 1));
        }
    }
    !c
}
pub fn append(b: &mut Vec<u8>, sequence: u64, payload: &[u8]) {
    let mut data = sequence.to_le_bytes().to_vec();
    data.extend_from_slice(payload);
    b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    b.extend_from_slice(&crc(&data).to_le_bytes());
    b.extend_from_slice(&data);
}
pub fn segment(h: Header, payloads: &[&[u8]]) -> Vec<u8> {
    let mut b = ricevanta_spool::encode_header(h).unwrap().to_vec();
    for (i, p) in payloads.iter().enumerate() {
        append(&mut b, h.first_sequence + i as u64, p);
    }
    b
}
pub fn plain(payloads: &[&[u8]]) -> Vec<u8> {
    let mut p = Vec::new();
    for x in payloads {
        p.extend_from_slice(x);
        p.push(b'\n');
    }
    p
}
// Independent RFC 8878 inspector. Does not call a codec or assume size width.
pub fn inspect(body: &[u8], size: usize) {
    let b = &body[48..];
    assert_eq!(&b[..4], &[0x28, 0xb5, 0x2f, 0xfd]);
    let flag = b[4];
    assert_eq!(flag & 0x1b, 0);
    assert_ne!(flag & 4, 0);
    let single = flag & 0x20 != 0;
    let width = match flag >> 6 {
        0 => usize::from(single),
        1 => 2,
        2 => 4,
        _ => 8,
    };
    assert_ne!(width, 0);
    let mut pos = 5;
    let window = if single {
        size as u64
    } else {
        let wd = b[pos];
        pos += 1;
        let base = 1u64 << (10 + (wd >> 3));
        base + (base / 8) * u64::from(wd & 7)
    };
    assert!(window <= 4_194_304);
    let mut value = 0u64;
    for i in 0..width {
        value |= u64::from(b[pos + i]) << (8 * i);
    }
    if width == 2 {
        value += 256;
    }
    assert_eq!(value, size as u64);
    pos += width;
    loop {
        let word = u32::from(b[pos]) | (u32::from(b[pos + 1]) << 8) | (u32::from(b[pos + 2]) << 16);
        pos += 3;
        let kind = (word >> 1) & 3;
        assert_ne!(kind, 3);
        let block = (word >> 3) as usize;
        assert!(block <= 131_072);
        pos += if kind == 1 { 1 } else { block };
        assert!(pos <= b.len());
        if word & 1 != 0 {
            break;
        }
    }
    assert_eq!(pos + 4, b.len());
}
pub fn verify(h: Header, payloads: &[&[u8]]) -> ricevanta_batch::SealedBatch {
    let input = segment(h, payloads);
    let original = input.clone();
    let out = ricevanta_batch::seal(&input).unwrap();
    assert_eq!(input, original);
    let p = plain(payloads);
    inspect(out.body(), p.len());
    assert_eq!(
        zstd::bulk::decompress(&out.body()[48..], p.len()).unwrap(),
        p
    );
    let last = h.first_sequence + (payloads.len() as u64 - 1);
    assert_eq!(
        out.header_value(),
        format!(
            "v=1;class={};epoch={};segment={};first={};last={};count={}",
            h.class.as_str(),
            h.stream_epoch,
            h.segment_id,
            h.first_sequence,
            last,
            payloads.len()
        )
    );
    assert_eq!(out.body()[9], h.class as u8);
    for (offset, value) in [
        (12, h.stream_epoch),
        (20, h.segment_id),
        (28, h.first_sequence),
        (36, last),
    ] {
        assert_eq!(&out.body()[offset..offset + 8], &value.to_le_bytes());
    }
    assert_eq!(&out.body()[44..48], &(payloads.len() as u32).to_le_bytes());
    out
}

pub fn mutation_cases(seed: u64, count: usize) -> impl Iterator<Item = Vec<u8>> {
    let mut state = seed;
    (0..count).map(move |case| {
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let first = next() % 1024;
        let h = Header {
            class: SpoolClass::try_from((next() % 5 + 1) as u8).unwrap(),
            stream_epoch: next().max(1),
            segment_id: next(),
            first_sequence: first,
        };
        let n = (next() % 16 + 1) as usize;
        let mut payloads = Vec::new();
        for _ in 0..n {
            let len = (next() % 512 + 1) as usize;
            let mut p = Vec::with_capacity(len);
            for _ in 0..len {
                let byte = next() as u8;
                p.push(if matches!(byte, 10 | 13) { b'x' } else { byte });
            }
            p[0] = b'x';
            payloads.push(p);
        }
        let ps: Vec<&[u8]> = payloads.iter().map(Vec::as_slice).collect();
        let mut input = segment(h, &ps);
        match case % 12 {
            0 | 10 => {}
            1 => {
                let pos = next() as usize % input.len();
                input[pos] ^= (next() as u8).max(1);
            }
            2 => {
                input.truncate(next() as usize % input.len());
            }
            3 => {
                input[32..36].copy_from_slice(&1_048_577u32.to_le_bytes());
            }
            4 => {
                input[36] ^= 1;
            }
            5 => {
                input = ricevanta_spool::encode_header(h).unwrap().to_vec();
                append(&mut input, first + 1, &payloads[0]);
            }
            6 => {
                let bad: &[u8] = match (case / 12) % 5 {
                    0 => b"",
                    1 => b" \t",
                    2 => b"\xef\xbb\xbf\n",
                    3 => b"x\r\n",
                    _ => b"x\r",
                };
                input = ricevanta_spool::encode_header(h).unwrap().to_vec();
                for (i, p) in payloads.iter().enumerate() {
                    append(
                        &mut input,
                        first + i as u64,
                        if i == n / 2 { bad } else { p },
                    );
                }
            }
            7 => {
                let pos = next() as usize % 32;
                input[pos] ^= 0xff;
            }
            8 => {
                input.extend_from_slice(&[1, 0, 0]);
            }
            9 => {
                input = ricevanta_spool::encode_header(header(u64::MAX))
                    .unwrap()
                    .to_vec();
                append(&mut input, u64::MAX, b"x");
                if next() & 1 != 0 {
                    append(&mut input, 0, b"y");
                }
            }
            _ => {
                input.truncate(32);
            }
        }
        input
    })
}
