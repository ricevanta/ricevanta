//! The `kauth_filesec` decoder over raw reply bytes (plan Task 4). Pure, so
//! it runs on every host. The layout values here are written out from xnu's
//! `kauth.h` independently of the crate's constants.

use ricevanta_os_macos::acl::{ATTR_BUFFER_BYTES, AclFinding, check_extended_security};

const MAGIC: u32 = 0x012c_c16d;
const NOACL: u32 = u32::MAX;
const PERMIT: u32 = 1;
const DENY: u32 = 2;
const AUDIT: u32 = 3;
const ALARM: u32 = 4;
// Flags above the kind mask, such as inheritance bits, do not change the kind.
const FILE_INHERIT: u32 = 1 << 5;

fn ace(kind_and_flags: u32) -> Vec<u8> {
    let mut entry = vec![0xab; 16]; // ace_applicable GUID
    entry.extend_from_slice(&kind_and_flags.to_ne_bytes());
    entry.extend_from_slice(&0x0000_0004u32.to_ne_bytes()); // ace_rights
    entry
}

fn filesec(count: u32, entries: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = MAGIC.to_ne_bytes().to_vec();
    bytes.extend_from_slice(&[0x11; 32]); // owner and group GUIDs
    bytes.extend_from_slice(&count.to_ne_bytes());
    bytes.extend_from_slice(&0u32.to_ne_bytes()); // acl_flags
    for entry in entries {
        bytes.extend_from_slice(entry);
    }
    bytes
}

/// A reply: total length, the attribute reference (offset relative to the
/// reference), then the attribute, padded to the buffer size.
fn reply_with(offset: i32, length: u32, attribute: &[u8], total: Option<u32>) -> Vec<u8> {
    let mut reply = Vec::new();
    let natural = (12 + attribute.len()) as u32;
    reply.extend_from_slice(&total.unwrap_or(natural).to_ne_bytes());
    reply.extend_from_slice(&offset.to_ne_bytes());
    reply.extend_from_slice(&length.to_ne_bytes());
    reply.extend_from_slice(attribute);
    reply.resize(ATTR_BUFFER_BYTES, 0);
    reply
}

fn reply(attribute: &[u8]) -> Vec<u8> {
    reply_with(8, attribute.len() as u32, attribute, None)
}

fn malformed(result: Result<(), AclFinding>) -> bool {
    matches!(result, Err(AclFinding::Malformed(_)))
}

#[test]
fn buffer_holds_the_largest_acl() {
    assert_eq!(ATTR_BUFFER_BYTES, 3_128);
    assert_eq!(ATTR_BUFFER_BYTES, 4 + 8 + 44 + 128 * 24);
}

#[test]
fn no_acl_passes() {
    // An empty attribute.
    assert_eq!(
        check_extended_security(&reply_with(8, 0, &[], None)),
        Ok(())
    );
    // KAUTH_FILESEC_NOACL.
    assert_eq!(
        check_extended_security(&reply(&filesec(NOACL, &[]))),
        Ok(())
    );
    // An ACL with no entries.
    assert_eq!(check_extended_security(&reply(&filesec(0, &[]))), Ok(()));
}

#[test]
fn deny_only_entries_pass() {
    let entries = [ace(DENY), ace(DENY | FILE_INHERIT)];
    assert_eq!(
        check_extended_security(&reply(&filesec(2, &entries))),
        Ok(())
    );
    let full: Vec<_> = (0..128).map(|_| ace(DENY)).collect();
    let attribute = filesec(128, &full);
    assert_eq!(12 + attribute.len(), ATTR_BUFFER_BYTES);
    assert_eq!(check_extended_security(&reply(&attribute)), Ok(()));
}

#[test]
fn any_other_kind_fails_whoever_it_names() {
    for kind in [PERMIT, PERMIT | FILE_INHERIT, AUDIT, ALARM, 0, 5, 0xf] {
        let entries = [ace(DENY), ace(kind)];
        assert_eq!(
            check_extended_security(&reply(&filesec(2, &entries))),
            Err(AclFinding::Entry {
                index: 1,
                kind: kind & 0xf
            }),
            "kind {kind:#x}"
        );
    }
}

#[test]
fn malformed_attributes_fail_closed() {
    let good = filesec(1, &[ace(DENY)]);
    // Bad magic.
    let mut bad_magic = good.clone();
    bad_magic[0] ^= 1;
    assert!(malformed(check_extended_security(&reply(&bad_magic))));
    // Header cut short.
    assert!(malformed(check_extended_security(&reply(&good[..43]))));
    // Entries that are not a whole number of kauth_ace.
    assert!(malformed(check_extended_security(&reply(
        &good[..good.len() - 1]
    ))));
    // A count that does not match the attribute length (truncated ACL).
    let short = filesec(2, &[ace(DENY)]);
    assert!(malformed(check_extended_security(&reply(&short))));
    let long = filesec(0, &[ace(DENY)]);
    assert!(malformed(check_extended_security(&reply(&long))));
}

#[test]
fn lengths_and_offsets_outside_the_reply_fail_closed() {
    let attribute = filesec(1, &[ace(DENY)]);
    let len = attribute.len() as u32;
    // A total length above the bytes returned.
    let mut over = reply(&attribute);
    over[..4].copy_from_slice(&(ATTR_BUFFER_BYTES as u32 + 1).to_ne_bytes());
    assert!(malformed(check_extended_security(&over)));
    // The attribute reaching past the total length.
    let cut_total = reply_with(8, len, &attribute, Some(12 + len - 1));
    assert!(malformed(check_extended_security(&cut_total)));
    // An offset past the end, a negative offset, and one inside the header.
    for offset in [i32::MAX, ATTR_BUFFER_BYTES as i32, -4, -1, 0, 4] {
        let r = reply_with(offset, len, &attribute, None);
        assert!(malformed(check_extended_security(&r)), "offset {offset}");
    }
    // An attribute length past the end.
    for length in [len + 1, u32::MAX] {
        let r = reply_with(8, length, &attribute, None);
        assert!(malformed(check_extended_security(&r)), "length {length}");
    }
    // Replies too short to hold the header fields.
    for size in [0, 3, 4, 11] {
        assert!(
            malformed(check_extended_security(&vec![0u8; size])),
            "size {size}"
        );
    }
    let mut no_reference = vec![0u8; 16];
    no_reference[..4].copy_from_slice(&8u32.to_ne_bytes());
    assert!(malformed(check_extended_security(&no_reference)));
}
