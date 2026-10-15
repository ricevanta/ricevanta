//! The Windows owner and DACL rule over decoded entries. Pure, so it runs on
//! every host.

use ricevanta_os::Reason;
use ricevanta_os_windows::dacl::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, ADMINISTRATORS, Ace, LOCAL_SYSTEM,
    SecurityFacts, evaluate,
};

const USERS: &str = "S-1-5-32-545";
const CREATOR_OWNER: &str = "S-1-3-0";
const FULL: u32 = 0x001f_01ff;
const OBJECT_INHERIT: u8 = 0x1;
const CONTAINER_INHERIT: u8 = 0x2;
const INHERIT_ONLY: u8 = 0x8;
// Types the rule must refuse without decoding them.
const ACCESS_ALLOWED_OBJECT_ACE_TYPE: u8 = 5;
const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;
const ACCESS_ALLOWED_COMPOUND_ACE_TYPE: u8 = 4;
const SYSTEM_AUDIT_ACE_TYPE: u8 = 2;

fn allow(sid: &str, flags: u8, mask: u32) -> Ace {
    Ace {
        ace_type: ACCESS_ALLOWED_ACE_TYPE,
        flags,
        mask,
        sid: Some(sid.to_owned()),
    }
}

fn deny(sid: &str, mask: u32) -> Ace {
    Ace {
        ace_type: ACCESS_DENIED_ACE_TYPE,
        flags: 0,
        mask,
        sid: Some(sid.to_owned()),
    }
}

/// The installer's tree: SYSTEM and Administrators full control, inherited.
fn prepared(extra: Vec<Ace>) -> SecurityFacts {
    let mut dacl = vec![
        allow(LOCAL_SYSTEM, OBJECT_INHERIT | CONTAINER_INHERIT, FULL),
        allow(ADMINISTRATORS, OBJECT_INHERIT | CONTAINER_INHERIT, FULL),
    ];
    dacl.extend(extra);
    SecurityFacts {
        owner: Some(ADMINISTRATORS.to_owned()),
        dacl: Some(dacl),
    }
}

#[test]
fn installer_tree_passes() {
    assert_eq!(evaluate(&prepared(vec![])), Ok(()));
    let mut system_owned = prepared(vec![]);
    system_owned.owner = Some(LOCAL_SYSTEM.to_owned());
    assert_eq!(evaluate(&system_owned), Ok(()));
}

#[test]
fn owner_must_be_system_or_administrators() {
    let mut facts = prepared(vec![]);
    let user = "S-1-5-21-1-2-3-1001";
    facts.owner = Some(user.to_owned());
    assert_eq!(
        evaluate(&facts),
        Err(Reason::OwnerSid {
            sid: user.to_owned()
        })
    );
    facts.owner = None;
    assert!(matches!(evaluate(&facts), Err(Reason::OwnerSid { .. })));
}

#[test]
fn null_or_absent_dacl_fails() {
    let mut facts = prepared(vec![]);
    facts.dacl = None;
    assert_eq!(evaluate(&facts), Err(Reason::InsecureAcl { sid: None }));
}

#[test]
fn any_right_for_another_principal_fails() {
    for (ace, name) in [
        (
            allow(USERS, OBJECT_INHERIT | CONTAINER_INHERIT, 0x0013_01bf),
            "Users modify",
        ),
        (
            allow(USERS, OBJECT_INHERIT | CONTAINER_INHERIT, 0x0012_00a9),
            "Users RX",
        ),
        (allow(USERS, 0, 0x0010_0000), "Users synchronize only"),
        (allow(USERS, 0, 0x0012_0089), "Users read"),
        (
            allow(
                USERS,
                OBJECT_INHERIT | CONTAINER_INHERIT | INHERIT_ONLY,
                0x0012_0116,
            ),
            "Users inherit-only write",
        ),
        (
            allow(
                CREATOR_OWNER,
                OBJECT_INHERIT | CONTAINER_INHERIT | INHERIT_ONLY,
                0x0012_0116,
            ),
            "CREATOR OWNER write",
        ),
    ] {
        let sid = ace.sid.clone();
        assert_eq!(
            evaluate(&prepared(vec![ace])),
            Err(Reason::InsecureAcl { sid }),
            "{name}"
        );
    }
}

#[test]
fn deny_entries_and_empty_masks_pass() {
    assert_eq!(evaluate(&prepared(vec![deny(USERS, 0x0012_0116)])), Ok(()));
    assert_eq!(evaluate(&prepared(vec![allow(USERS, 0, 0)])), Ok(()));
}

#[test]
fn other_entry_types_fail_closed() {
    for ace_type in [
        ACCESS_ALLOWED_OBJECT_ACE_TYPE,
        ACCESS_ALLOWED_CALLBACK_ACE_TYPE,
        ACCESS_ALLOWED_COMPOUND_ACE_TYPE,
        SYSTEM_AUDIT_ACE_TYPE,
        0xff,
    ] {
        let ace = Ace {
            ace_type,
            flags: 0,
            mask: 0,
            sid: None,
        };
        assert_eq!(
            evaluate(&prepared(vec![ace])),
            Err(Reason::InsecureAcl { sid: None }),
            "type {ace_type}"
        );
    }
    // An allowed entry whose trustee could not be decoded fails closed too.
    let undecoded = Ace {
        ace_type: ACCESS_ALLOWED_ACE_TYPE,
        flags: 0,
        mask: FULL,
        sid: None,
    };
    assert_eq!(
        evaluate(&prepared(vec![undecoded])),
        Err(Reason::InsecureAcl { sid: None })
    );
}

#[test]
fn owner_is_judged_before_the_dacl() {
    let mut facts = prepared(vec![allow(USERS, 0, FULL)]);
    facts.owner = Some(USERS.to_owned());
    assert_eq!(
        evaluate(&facts),
        Err(Reason::OwnerSid {
            sid: USERS.to_owned()
        })
    );
}
