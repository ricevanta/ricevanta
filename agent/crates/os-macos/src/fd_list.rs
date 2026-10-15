//! Validation of fixed descriptor-list replies, independent of native calls.

use ricevanta_os::SampleError;

pub(crate) fn validate_fd_bytes(
    written: usize,
    capacity: usize,
    entry: usize,
) -> Result<usize, SampleError> {
    if written >= capacity {
        return Err(SampleError::Unsupported);
    }
    if !written.is_multiple_of(entry) {
        return Err(SampleError::Format {
            source: "PROC_PIDLISTFDS",
        });
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ricevanta_os::SampleError;

    #[test]
    fn full_descriptor_reply_is_unsupported_never_a_truncated_count() {
        assert_eq!(validate_fd_bytes(4088, 4096, 8), Ok(4088));
        assert_eq!(
            validate_fd_bytes(4096, 4096, 8),
            Err(SampleError::Unsupported)
        );
        assert_eq!(
            validate_fd_bytes(4104, 4096, 8),
            Err(SampleError::Unsupported)
        );
        assert!(matches!(
            validate_fd_bytes(4089, 4096, 8),
            Err(SampleError::Format { .. })
        ));
    }
}
