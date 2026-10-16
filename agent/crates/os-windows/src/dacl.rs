//! The owner and DACL rule of spec section 3.1, as a pure function over
//! decoded security facts, so it is tested on every host and the native
//! code only decodes.

use ricevanta_os::Reason;

/// Local System.
pub const LOCAL_SYSTEM: &str = "S-1-5-18";
/// The built-in Administrators group.
pub const ADMINISTRATORS: &str = "S-1-5-32-544";
/// `ACE_HEADER.AceType` of an access-allowed entry, the documented value of
/// `ACCESS_ALLOWED_ACE_TYPE`; declared here because `windows-sys` places
/// the constant in a feature outside the licensed union.
pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
/// `ACE_HEADER.AceType` of an access-denied entry (`ACCESS_DENIED_ACE_TYPE`).
pub const ACCESS_DENIED_ACE_TYPE: u8 = 1;

/// One decoded access control entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    /// `ACE_HEADER.AceType`.
    pub ace_type: u8,
    /// `ACE_HEADER.AceFlags`; inherit-only entries are judged like any other.
    pub flags: u8,
    /// The access mask of an allowed or denied entry, 0 for other types.
    pub mask: u32,
    /// The trustee in string form for allowed and denied entries; `None`
    /// for entry types that are not decoded.
    pub sid: Option<String>,
}

/// The owner and DACL read from an opened handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecurityFacts {
    /// The owner SID in string form, `None` when the descriptor has none.
    pub owner: Option<String>,
    /// The DACL entries; `None` when the DACL is absent or null.
    pub dacl: Option<Vec<Ace>>,
}

fn trusted(sid: &str) -> bool {
    sid == LOCAL_SYSTEM || sid == ADMINISTRATORS
}

/// The rule: owner exactly Local System or Administrators; a DACL that is
/// present and not null; every access-allowed entry for any other trustee
/// (`CREATOR OWNER` included) has an empty mask, whatever its flags, so no
/// read, execute, synchronize or attribute right goes to anyone else;
/// access-denied entries are accepted; any other entry type (object,
/// callback or compound) fails closed. The first failing property in that
/// order is reported.
pub fn evaluate(facts: &SecurityFacts) -> Result<(), Reason> {
    match &facts.owner {
        Some(owner) if trusted(owner) => {}
        Some(owner) => return Err(Reason::OwnerSid { sid: owner.clone() }),
        None => {
            return Err(Reason::OwnerSid { sid: String::new() });
        }
    }
    let Some(entries) = &facts.dacl else {
        return Err(Reason::InsecureAcl { sid: None });
    };
    for ace in entries {
        match ace.ace_type {
            ACCESS_ALLOWED_ACE_TYPE => match &ace.sid {
                Some(sid) if trusted(sid) || ace.mask == 0 => {}
                sid => {
                    return Err(Reason::InsecureAcl { sid: sid.clone() });
                }
            },
            ACCESS_DENIED_ACE_TYPE => {}
            _ => {
                return Err(Reason::InsecureAcl {
                    sid: ace.sid.clone(),
                });
            }
        }
    }
    Ok(())
}
