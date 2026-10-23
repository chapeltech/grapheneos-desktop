use wonad_broker_core::authority::{Admission, Caller, OpenError, Revocation};
use wonad_broker_core::layout::Rect;
use wonad_broker_core::native_authority::*;
use wonad_broker_core::native_frame::{Display, Topology, API_VERSION};
use wonad_broker_core::ResultCode;

const DISPLAY: Display = Display {
    token: 100,
    display_id: 2,
    bounds: Rect {
        left: 0,
        top: 0,
        right: 1920,
        bottom: 1080,
    },
    density_dpi: 160,
    secure: true,
    shell_generation: 0,
};
fn owner() -> Caller<'static> {
    Caller {
        uid: 10152,
        user_id: 0,
        package_name: "org.wonad.desktop",
        signer_sha256: [0xab; 32],
        shared_uid: false,
    }
}
fn state<'a>(revision: i64, displays: &'a [Display]) -> Environment<'a> {
    Environment {
        active_user_id: 0,
        user_enabled: true,
        locked: false,
        topology: Topology { revision, displays },
    }
}
fn opened() -> (Authority<'static>, Lease) {
    let mut auth = Authority::new("org.wonad.desktop", [0xab; 32], 100).unwrap();
    let lease = auth
        .open(&owner(), &state(1, &[DISPLAY]), API_VERSION, 100)
        .unwrap();
    (auth, lease)
}
fn request(id: i64, revision: i64) -> Request {
    Request {
        request_id: id,
        base_revision: 7,
        actual_revision: 7,
        topology_revision: revision,
    }
}

#[test]
fn version_three_is_real_and_cannot_downgrade_or_upgrade() {
    for version in [0, 1, 2, 4, i32::MAX] {
        let mut auth = Authority::new("org.wonad.desktop", [0xab; 32], 100).unwrap();
        assert_eq!(
            auth.open(&owner(), &state(1, &[DISPLAY]), version, 100),
            Err(OpenError::UnsupportedVersion)
        );
        assert!(auth.open(&owner(), &state(1, &[DISPLAY]), 3, 100).is_ok());
    }
    let (mut auth, _) = opened();
    assert_eq!(
        auth.open(&owner(), &state(1, &[DISPLAY]), 3, 100),
        Err(OpenError::AlreadyOpen)
    );
}

#[test]
fn fresh_exact_owner_signer_user_and_live_clock_are_required() {
    let (mut auth, lease) = opened();
    for invalid in [
        Caller {
            uid: 10153,
            ..owner()
        },
        Caller {
            uid: 1000,
            ..owner()
        },
        Caller {
            user_id: 1,
            ..owner()
        },
        Caller {
            uid: 110152,
            user_id: 1,
            ..owner()
        },
        Caller {
            shared_uid: true,
            ..owner()
        },
        Caller {
            signer_sha256: [0xcd; 32],
            ..owner()
        },
        Caller {
            package_name: "other",
            ..owner()
        },
    ] {
        assert!(!auth.owns(&invalid, lease.generation, 100));
        assert!(!auth.heartbeat(&invalid, lease.generation, 1, 100));
        assert!(!auth.release(&invalid, lease.generation, 100));
        assert_eq!(
            auth.begin_request(&invalid, lease.generation, request(1, 1), 100),
            Admission::Revoked
        );
    }
    assert!(!auth.heartbeat(&owner(), lease.generation, 0, 100));
    assert!(auth.heartbeat(&owner(), lease.generation, 1, 200));
    assert!(!auth.heartbeat(&owner(), lease.generation, 1, 201));
    assert!(!auth.owns(&owner(), lease.generation, 199));
    assert!(auth.owns(&owner(), lease.generation, 5199));
    assert!(!auth.owns(&owner(), lease.generation, 5200));
}

#[test]
fn request_lifecycle_ignores_stale_revision_generation_and_callback() {
    let (mut auth, lease) = opened();
    assert_eq!(
        auth.begin_request(&owner(), lease.generation, request(1, 1), 100),
        Admission::Accepted
    );
    assert_eq!(
        auth.begin_request(&owner(), lease.generation, request(2, 1), 100),
        Admission::Busy
    );
    assert!(!auth.finish_request(lease.generation + 1, 1, 1));
    assert!(!auth.finish_request(lease.generation, 2, 1));
    assert!(!auth.finish_request(lease.generation, 1, 2));
    assert!(auth.finish_request(lease.generation, 1, 1));
    assert_eq!(
        auth.begin_request(&owner(), lease.generation, request(1, 1), 100),
        Admission::Stale
    );
    for request in [
        Request {
            actual_revision: 8,
            ..request(2, 1)
        },
        request(2, 2),
    ] {
        assert_eq!(
            auth.begin_request(&owner(), lease.generation, request, 100),
            Admission::Stale
        );
    }
    assert_eq!(
        auth.begin_request(&owner(), lease.generation, request(2, 1), 100),
        Admission::Accepted
    );
}

#[test]
fn native_incarnation_replacement_requires_revision_and_invalidates_completion() {
    let (mut auth, lease) = opened();
    assert_eq!(
        auth.begin_request(&owner(), lease.generation, request(1, 1), 100),
        Admission::Accepted
    );
    let replacement = Display {
        token: 101,
        ..DISPLAY
    };
    assert_eq!(
        auth.update_topology(
            &owner(),
            lease.generation,
            &state(1, &[replacement]).topology,
            100
        ),
        ResultCode::Stale
    );
    assert_eq!(
        auth.update_topology(
            &owner(),
            lease.generation,
            &state(2, &[replacement]).topology,
            100
        ),
        ResultCode::Applied
    );
    assert!(!auth.finish_request(lease.generation, 1, 1));
    assert_eq!(auth.topology().unwrap().displays[0].token, 101);
    assert_eq!(
        auth.begin_request(&owner(), lease.generation, request(2, 1), 100),
        Admission::Stale
    );
    assert_eq!(
        auth.begin_request(&owner(), lease.generation, request(2, 2), 100),
        Admission::Accepted
    );
    assert_eq!(
        auth.reconcile(&state(3, &[]), Some(&owner()), 101),
        Some(Revocation::Undocked)
    );
    assert!(!auth.owns(&owner(), lease.generation, 101));
}

#[test]
fn lock_disable_user_identity_death_and_expiry_revoke() {
    for (disabled, locked, user, now, caller, reason) in [
        (true, false, 0, 101, Some(owner()), Revocation::Disabled),
        (false, true, 0, 101, Some(owner()), Revocation::Locked),
        (false, false, 1, 101, Some(owner()), Revocation::UserChanged),
        (false, false, 0, 101, None, Revocation::IdentityChanged),
        (
            false,
            false,
            0,
            5100,
            Some(owner()),
            Revocation::ClientFailed,
        ),
    ] {
        let (mut auth, lease) = opened();
        let mut environment = state(1, &[DISPLAY]);
        environment.active_user_id = user;
        environment.user_enabled = !disabled;
        environment.locked = locked;
        assert_eq!(
            auth.reconcile(&environment, caller.as_ref(), now),
            Some(reason)
        );
        assert!(!auth.owns(&owner(), lease.generation, now));
        assert!(auth.topology().is_none());
    }
    let (mut auth, lease) = opened();
    assert!(!auth.client_died(lease.generation + 1));
    assert!(auth.client_died(lease.generation));
    let next = auth.open(&owner(), &state(2, &[DISPLAY]), 3, 101).unwrap();
    assert!(next.generation > lease.generation);
    assert!(!auth.client_died(lease.generation));
    assert!(auth.owns(&owner(), next.generation, 101));
}
