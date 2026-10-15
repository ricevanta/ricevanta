//! The portable Unix protection rules of spec section 3.1, evaluated over
//! facts read from an opened descriptor.

use ricevanta_os::unix::{
    Facts, Kind, check_config_file, check_config_parent, check_created_file, check_dir, dir_owner,
};
use ricevanta_os::{
    DirKind, FileKind, FootprintMetric, LifecycleState, Mode, ProcessSample, Reason,
};

const EUID: u32 = 1000;

fn facts(kind: Kind, mode: u32, uid: u32) -> Facts {
    Facts { kind, mode, uid }
}

#[test]
fn config_file_rules() {
    for mode in [0o600, 0o400] {
        assert_eq!(
            check_config_file(&facts(Kind::Regular, mode, EUID), EUID),
            Ok(())
        );
        assert_eq!(
            check_config_file(&facts(Kind::Regular, mode, 0), EUID),
            Ok(())
        );
    }
    for mode in [0o644, 0o640, 0o604, 0o700, 0o4600, 0o660, 0o200] {
        assert_eq!(
            check_config_file(&facts(Kind::Regular, mode, EUID), EUID),
            Err(Reason::Mode { mode }),
            "{mode:o}"
        );
    }
    assert_eq!(
        check_config_file(&facts(Kind::Regular, 0o600, 4242), EUID),
        Err(Reason::Owner { uid: 4242 })
    );
    // Running as root, only root may own the file.
    assert_eq!(
        check_config_file(&facts(Kind::Regular, 0o600, EUID), 0),
        Err(Reason::Owner { uid: EUID })
    );
    for kind in [Kind::Directory, Kind::Symlink, Kind::Other] {
        assert_eq!(
            check_config_file(&facts(kind, 0o600, EUID), EUID),
            Err(Reason::NotRegularFile)
        );
    }
    // Type is decided before owner and mode.
    assert_eq!(
        check_config_file(&facts(Kind::Other, 0o666, 4242), EUID),
        Err(Reason::NotRegularFile)
    );
    // Owner is decided before mode.
    assert_eq!(
        check_config_file(&facts(Kind::Regular, 0o666, 4242), EUID),
        Err(Reason::Owner { uid: 4242 })
    );
}

#[test]
fn config_parent_rules() {
    for mode in [0o755, 0o700, 0o555, 0o1755] {
        assert_eq!(
            check_config_parent(&facts(Kind::Directory, mode, 0), EUID),
            Ok(()),
            "{mode:o}"
        );
    }
    for mode in [0o775, 0o757, 0o777, 0o1777] {
        assert_eq!(
            check_config_parent(&facts(Kind::Directory, mode, 0), EUID),
            Err(Reason::ParentWritable { mode }),
            "{mode:o}"
        );
    }
    assert_eq!(
        check_config_parent(&facts(Kind::Directory, 0o755, 4242), EUID),
        Err(Reason::Owner { uid: 4242 })
    );
    assert_eq!(
        check_config_parent(&facts(Kind::Regular, 0o755, 0), EUID),
        Err(Reason::NotDirectory)
    );
}

#[test]
fn directory_rules() {
    assert_eq!(dir_owner(Mode::Service, EUID), 0);
    assert_eq!(dir_owner(Mode::Run, EUID), EUID);
    assert_eq!(DirKind::State.unix_mode(), 0o700);
    assert_eq!(DirKind::Log.unix_mode(), 0o700);
    assert_eq!(DirKind::Runtime.unix_mode(), 0o755);
    assert_eq!(DirKind::DataRoot.unix_mode(), 0o755);
    let ok = |kind: DirKind, mode, uid, run| {
        check_dir(&facts(Kind::Directory, mode, uid), kind, run, EUID)
    };
    assert_eq!(ok(DirKind::State, 0o700, EUID, Mode::Run), Ok(()));
    assert_eq!(ok(DirKind::State, 0o700, 0, Mode::Service), Ok(()));
    assert_eq!(
        ok(DirKind::State, 0o750, EUID, Mode::Run),
        Err(Reason::Mode { mode: 0o750 })
    );
    // An existing directory must match exactly; narrower also fails.
    assert_eq!(
        ok(DirKind::Runtime, 0o700, EUID, Mode::Run),
        Err(Reason::Mode { mode: 0o700 })
    );
    assert_eq!(ok(DirKind::Runtime, 0o755, EUID, Mode::Run), Ok(()));
    // Service mode requires root even when the effective user differs.
    assert_eq!(
        ok(DirKind::Log, 0o700, EUID, Mode::Service),
        Err(Reason::Owner { uid: EUID })
    );
    // Run mode requires the effective user, not root.
    assert_eq!(
        ok(DirKind::Log, 0o700, 0, Mode::Run),
        Err(Reason::Owner { uid: 0 })
    );
    assert_eq!(
        check_dir(
            &facts(Kind::Symlink, 0o700, EUID),
            DirKind::State,
            Mode::Run,
            EUID
        ),
        Err(Reason::NotDirectory)
    );
}

#[test]
fn created_file_rules() {
    assert_eq!(FileKind::HealthDocument.unix_mode(), 0o644);
    assert_eq!(FileKind::Log.unix_mode(), 0o600);
    assert_eq!(
        check_created_file(&facts(Kind::Regular, 0o600, EUID), EUID),
        Ok(())
    );
    assert_eq!(
        check_created_file(&facts(Kind::Regular, 0o600, 0), EUID),
        Err(Reason::Owner { uid: 0 })
    );
    assert_eq!(
        check_created_file(&facts(Kind::Other, 0o600, EUID), EUID),
        Err(Reason::NotRegularFile)
    );
}

#[test]
fn tokens() {
    assert_eq!(FootprintMetric::Pss.as_str(), "pss");
    assert_eq!(FootprintMetric::PhysFootprint.as_str(), "phys_footprint");
    assert_eq!(
        FootprintMetric::PrivateWorkingSet.as_str(),
        "private_working_set"
    );
    let states = [
        (LifecycleState::Starting, "starting"),
        (LifecycleState::Ready, "ready"),
        (LifecycleState::Stopping, "stopping"),
        (LifecycleState::Stopped, "stopped"),
    ];
    for (state, token) in states {
        assert_eq!(state.as_str(), token);
    }
    let sample = ProcessSample {
        footprint_bytes: 1,
        footprint_metric: FootprintMetric::Pss,
        cpu_user_ms: 0,
        cpu_system_ms: 0,
        threads: 1,
        descriptors: ricevanta_os::Descriptors::Fds(3),
    };
    assert_eq!(sample.clone(), sample);
}
