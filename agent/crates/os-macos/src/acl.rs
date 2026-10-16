//! The macOS extended-ACL rule of spec section 3.1, as a pure function over
//! the bytes `fgetattrlist(ATTR_CMN_EXTENDED_SECURITY)` returns, so it is
//! tested on every host and the native code only fills the buffer.
//!
//! `libc` declares no ACL types, so the `kauth_filesec` layout and the
//! `KAUTH_*` values below are constants taken from xnu's `bsd/sys/kauth.h`
//! (<https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/kauth.h>),
//! not foreign declarations. The kernel packs the ACL in host byte order.

/// The reply buffer: a `u_int32_t` total length, one 8-byte
/// `attrreference_t`, a 44-byte `kauth_filesec` header and
/// `KAUTH_ACL_MAX_ENTRIES` (128) entries of 24 bytes.
pub const ATTR_BUFFER_BYTES: usize =
    4 + ATTRREFERENCE_BYTES + FILESEC_HEADER_BYTES + 128 * ACE_BYTES;

/// `sizeof(attrreference_t)`: `int32_t attr_dataoffset`, `u_int32_t attr_length`.
const ATTRREFERENCE_BYTES: usize = 8;
/// `KAUTH_FILESEC_MAGIC`.
const KAUTH_FILESEC_MAGIC: u32 = 0x012c_c16d;
/// `KAUTH_FILESEC_NOACL`: `(u_int32_t)(-1)` as the entry count.
const KAUTH_FILESEC_NOACL: u32 = u32::MAX;
/// `KAUTH_FILESEC_SIZE(0)`: magic (4), owner and group GUIDs (16 + 16),
/// `acl_entrycount` (4) and `acl_flags` (4).
const FILESEC_HEADER_BYTES: usize = 44;
/// The offset of `fsec_acl.acl_entrycount` in `kauth_filesec`.
const ENTRY_COUNT_OFFSET: usize = 36;
/// `sizeof(struct kauth_ace)`: `guid_t ace_applicable` (16), `u_int32_t
/// ace_flags` (4), `kauth_ace_rights_t ace_rights` (4).
const ACE_BYTES: usize = 24;
/// The offset of `ace_flags` in `kauth_ace`.
const ACE_FLAGS_OFFSET: usize = 16;
/// `KAUTH_ACE_KINDMASK`.
const KAUTH_ACE_KINDMASK: u32 = 0xf;
/// `KAUTH_ACE_DENY`, the only kind that passes: it can only take rights away.
const KAUTH_ACE_DENY: u32 = 2;

/// Why an object's extended security fails the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclFinding {
    /// An entry that is not a deny entry: `KAUTH_ACE_PERMIT` (1), audit (3),
    /// alarm (4) or an unknown kind.
    Entry {
        /// The entry's position.
        index: usize,
        /// `ace_flags & KAUTH_ACE_KINDMASK`.
        kind: u32,
    },
    /// The reply or the `kauth_filesec` cannot be trusted; fails closed.
    Malformed(&'static str),
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let field = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_ne_bytes(field.try_into().ok()?))
}

/// Applies the rule to the `fgetattrlist` reply `reply`, the bytes the call
/// returned. An empty attribute or an entry count of `KAUTH_FILESEC_NOACL`
/// means no ACL and passes; an ACL passes only when every entry is a deny
/// entry. Every offset and length is checked against the returned bytes
/// before use.
pub fn check_extended_security(reply: &[u8]) -> Result<(), AclFinding> {
    use AclFinding::Malformed;
    let total = u32_at(reply, 0).ok_or(Malformed("reply shorter than its length field"))? as usize;
    if total > reply.len() {
        return Err(Malformed("total length above the bytes returned"));
    }
    if total < 4 + ATTRREFERENCE_BYTES {
        return Err(Malformed("reply without an attribute reference"));
    }
    let returned = &reply[..total];
    let offset = u32_at(returned, 4).ok_or(Malformed("attribute reference cut"))? as i32;
    let length = u32_at(returned, 8).ok_or(Malformed("attribute reference cut"))? as usize;
    if length == 0 {
        // An empty attribute: the object has no ACL.
        return Ok(());
    }
    // `attr_dataoffset` is relative to the attribute reference itself.
    let start = usize::try_from(offset)
        .ok()
        .and_then(|o| o.checked_add(4))
        .ok_or(Malformed("attribute offset outside the reply"))?;
    let end = start
        .checked_add(length)
        .filter(|&end| end <= returned.len() && start >= 4 + ATTRREFERENCE_BYTES)
        .ok_or(Malformed("attribute outside the reply"))?;
    let filesec = &returned[start..end];
    if filesec.len() < FILESEC_HEADER_BYTES {
        return Err(Malformed("kauth_filesec header cut"));
    }
    if u32_at(filesec, 0) != Some(KAUTH_FILESEC_MAGIC) {
        return Err(Malformed("bad kauth_filesec magic"));
    }
    let count = u32_at(filesec, ENTRY_COUNT_OFFSET).ok_or(Malformed("entry count cut"))?;
    if count == KAUTH_FILESEC_NOACL {
        return Ok(());
    }
    let body = filesec.len() - FILESEC_HEADER_BYTES;
    if !body.is_multiple_of(ACE_BYTES) {
        return Err(Malformed("entries are not a whole number of kauth_ace"));
    }
    if usize::try_from(count).ok() != Some(body / ACE_BYTES) {
        return Err(Malformed("entry count does not match the attribute length"));
    }
    for index in 0..body / ACE_BYTES {
        let at = FILESEC_HEADER_BYTES + index * ACE_BYTES + ACE_FLAGS_OFFSET;
        let kind = u32_at(filesec, at).ok_or(Malformed("entry cut"))? & KAUTH_ACE_KINDMASK;
        if kind != KAUTH_ACE_DENY {
            return Err(AclFinding::Entry { index, kind });
        }
    }
    Ok(())
}
