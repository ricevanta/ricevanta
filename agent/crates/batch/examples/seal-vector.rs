//! Test-only bounded byte bridge. No durable files or transport behavior.
use ricevanta_batch::{Error, MAX_SEGMENT_BYTES, seal};
use std::io::{self, Read, Write};

fn name(error: &Error) -> &'static str {
    match error {
        Error::SegmentTooLarge { .. } => "SegmentTooLarge",
        Error::Spool(_) => "Spool",
        Error::Tail(_) => "Tail",
        Error::Empty => "Empty",
        Error::RecordCount { .. } => "RecordCount",
        Error::LineFraming { .. } => "LineFraming",
        Error::DecodedLimit { .. } => "DecodedLimit",
        Error::Compression(_) => "Compression",
        Error::CompressedLimit { .. } => "CompressedLimit",
    }
}
fn run() -> Result<(), &'static str> {
    let mut input = Vec::new();
    io::stdin()
        .lock()
        .take((MAX_SEGMENT_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| "Read")?;
    let batch = seal(&input).map_err(|e| name(&e))?;
    let mut output = io::stdout().lock();
    output
        .write_all(batch.header_value().as_bytes())
        .map_err(|_| "Write")?;
    output.write_all(b"\n").map_err(|_| "Write")?;
    output.write_all(batch.body()).map_err(|_| "Write")?;
    output.flush().map_err(|_| "Write")
}
fn main() {
    if let Err(variant) = run() {
        let _ = writeln!(io::stderr().lock(), "{variant}");
        std::process::exit(1);
    }
}
