use crate::Error;

fn map_error(error: std::io::Error) -> Error {
    Error::Compression(error)
}
fn check_length(length: usize) -> Result<(), Error> {
    if length > 5_000_000 {
        Err(Error::CompressedLimit { length })
    } else {
        Ok(())
    }
}

pub(crate) fn compress(plain: &[u8], descriptor: &[u8; 48]) -> Result<Vec<u8>, Error> {
    let mut encoder = zstd::bulk::Compressor::new(3).map_err(map_error)?;
    encoder.window_log(22).map_err(map_error)?;
    encoder.include_checksum(true).map_err(map_error)?;
    encoder.include_contentsize(true).map_err(map_error)?;
    encoder.include_dictid(false).map_err(map_error)?;
    encoder.long_distance_matching(false).map_err(map_error)?;
    let mut output = vec![0; 48 + zstd::zstd_safe::compress_bound(plain.len())];
    output[..48].copy_from_slice(descriptor);
    let length = encoder
        .compress_to_buffer(plain, &mut output[48..])
        .map_err(map_error)?;
    output.truncate(48 + length);
    check_length(output.len())?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compression_error_source() {
        let error = map_error(std::io::Error::other("private codec detail"));
        let cause = std::error::Error::source(&error).unwrap();
        assert_eq!(
            cause.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::Other
        );
        assert!(!error.to_string().contains("private"));
    }
    #[test]
    fn final_length_guard() {
        assert!(check_length(5_000_000).is_ok());
        assert!(matches!(
            check_length(5_000_001),
            Err(Error::CompressedLimit { length: 5_000_001 })
        ));
    }
}
