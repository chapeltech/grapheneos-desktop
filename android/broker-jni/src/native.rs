//! Private bounded v3 JNI frames. Caller/environment/current observations must
//! come from the OS. Never deserialize an APK snapshot into a trusted frame.
use super::{boolean, int, read_longs, rect, BAD_FRAME, EMPTY_RECT, PACKAGE};
use jni::objects::{JClass, JLongArray};
use jni::sys::{jboolean, jint, jlong};
use jni::JNIEnv;
use std::sync::Mutex;
use wonad_broker_core::authority::{Admission, Caller, OpenError};
use wonad_broker_core::native_authority::{Authority, Environment, Request};
use wonad_broker_core::native_frame::{self, Display, Topology, MAX_DISPLAYS};
use wonad_broker_core::native_picker::{Picker, Scope};
use wonad_broker_core::native_wire::{
    decode_frame, decode_snapshot, DISPLAY_ROW, MAX_CURRENT_LONGS, MAX_DESIRED_LONGS,
};
use wonad_broker_core::ResultCode;

pub(super) static AUTHORITY: Mutex<Option<Authority<'static>>> = Mutex::new(None);
static PICKER: Mutex<Picker> = Mutex::new(Picker::new());
const SESSION_MAX: usize = 19 + MAX_DISPLAYS * DISPLAY_ROW;
const EMPTY_DISPLAY: Display = Display {
    token: 0,
    display_id: 0,
    bounds: EMPTY_RECT,
    density_dpi: 0,
    secure: false,
    shell_generation: 0,
};

fn session(op: i32, v: &[i64], authority: &mut Authority<'_>) -> Option<i64> {
    if !(19..=SESSION_MAX).contains(&v.len()) {
        return None;
    }
    let count = usize::try_from(v[18]).ok()?;
    if count > MAX_DISPLAYS || v.len() != 19 + count * DISPLAY_ROW {
        return None;
    }
    let mut displays = [EMPTY_DISPLAY; MAX_DISPLAYS];
    for (display, row) in displays.iter_mut().zip(v[19..].chunks_exact(DISPLAY_ROW)) {
        *display = Display {
            token: row[0],
            display_id: int(row[1])?,
            bounds: rect(&row[2..6])?,
            density_dpi: int(row[6])?,
            secure: boolean(row[7])?,
            shell_generation: row[8],
        };
    }
    let caller = Caller {
        uid: int(v[6])?,
        user_id: int(v[7])?,
        package_name: if boolean(v[8])? { PACKAGE } else { "" },
        signer_sha256: core::array::from_fn(|index| v[10 + index / 8].to_be_bytes()[index % 8]),
        shared_uid: boolean(v[9])?,
    };
    let state = Environment {
        active_user_id: int(v[14])?,
        user_enabled: boolean(v[16])?,
        locked: boolean(v[17])?,
        topology: Topology {
            revision: v[15],
            displays: &displays[..count],
        },
    };
    let (now, generation, sequence, base, actual, version) =
        (v[0], v[1], v[2], v[3], v[4], int(v[5])?);
    Some(match op {
        1 => match authority.open(&caller, &state, version, now) {
            Ok(lease) => lease.generation,
            Err(OpenError::Unauthorized) => -1,
            Err(OpenError::UnsupportedVersion) => -2,
            Err(OpenError::AlreadyOpen) => -3,
            Err(OpenError::InvalidConfiguration | OpenError::Exhausted) => -4,
        },
        2 => authority
            .reconcile(&state, (caller.uid >= 0).then_some(&caller), now)
            .map_or(0, |reason| reason as i64),
        3 => i64::from(authority.heartbeat(&caller, generation, sequence, now)),
        4 => match authority.begin_request(
            &caller,
            generation,
            Request {
                request_id: sequence,
                base_revision: base,
                actual_revision: actual,
                topology_revision: v[15],
            },
            now,
        ) {
            Admission::Accepted => 0,
            Admission::Stale => ResultCode::Stale as i64,
            Admission::Busy => ResultCode::Busy as i64,
            Admission::Revoked => ResultCode::Revoked as i64,
        },
        5 => i64::from(authority.finish_request(generation, sequence, v[15])),
        6 => i64::from(authority.release(&caller, generation, now)),
        7 => i64::from(authority.client_died(generation)),
        8 => authority.update_topology(&caller, generation, &state.topology, now) as i64,
        _ => return None,
    })
}

#[no_mangle]
pub extern "system" fn Java_org_wonad_desktop_broker_BrokerNative_nativeSession(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    operation: jint,
    values: JLongArray<'_>,
) -> jlong {
    let Some((frame, count)) = read_longs::<SESSION_MAX>(&env, &values) else {
        return BAD_FRAME;
    };
    let Ok(mut slot) = AUTHORITY.lock() else {
        return BAD_FRAME;
    };
    let Some(authority) = slot.as_mut() else {
        return BAD_FRAME;
    };
    session(operation, &frame[..count], authority).unwrap_or(BAD_FRAME)
}

fn validate(current: &[i64], desired: &[i64]) -> Option<ResultCode> {
    let current = decode_snapshot(current)?;
    let desired = decode_frame(desired)?;
    Some(native_frame::validate(
        &current.snapshot(),
        &desired.frame(),
    ))
}

fn validate_signed(current: &[i64], desired: &[i64]) -> Option<ResultCode> {
    let current = decode_snapshot(current)?;
    let desired = decode_frame(desired)?;
    Some(native_frame::validate_signed(
        &current.snapshot(),
        &desired.frame(),
    ))
}

fn matches(current: &[i64], desired: &[i64]) -> Option<bool> {
    let current = decode_snapshot(current)?;
    let desired = decode_frame(desired)?;
    Some(native_frame::placements_match(
        &current.snapshot(),
        &desired.frame(),
    ))
}

#[no_mangle]
pub extern "system" fn Java_org_wonad_desktop_broker_BrokerNative_nativeValidateFrame(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    current: JLongArray<'_>,
    desired: JLongArray<'_>,
) -> jint {
    let Some((current, count)) = read_longs::<MAX_CURRENT_LONGS>(&env, &current) else {
        return ResultCode::Invalid as i32;
    };
    let Some((desired, desired_count)) = read_longs::<MAX_DESIRED_LONGS>(&env, &desired) else {
        return ResultCode::Invalid as i32;
    };
    validate(&current[..count], &desired[..desired_count]).unwrap_or(ResultCode::Invalid) as i32
}

/// Separate privileged facade for the negotiated additive signed RPC. Same
/// copied scalar arrays, no APK-supplied geometry-mode flag or native handles.
#[no_mangle]
pub extern "system" fn Java_org_wonad_desktop_broker_BrokerNative_nativeValidateSignedFrame(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    current: JLongArray<'_>,
    desired: JLongArray<'_>,
) -> jint {
    let Some((current, count)) = read_longs::<MAX_CURRENT_LONGS>(&env, &current) else {
        return ResultCode::Invalid as i32;
    };
    let Some((desired, desired_count)) = read_longs::<MAX_DESIRED_LONGS>(&env, &desired) else {
        return ResultCode::Invalid as i32;
    };
    validate_signed(&current[..count], &desired[..desired_count]).unwrap_or(ResultCode::Invalid)
        as i32
}

#[no_mangle]
pub extern "system" fn Java_org_wonad_desktop_broker_BrokerNative_nativeFrameMatches(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    current: JLongArray<'_>,
    desired: JLongArray<'_>,
) -> jboolean {
    let Some((current, count)) = read_longs::<MAX_CURRENT_LONGS>(&env, &current) else {
        return 0;
    };
    let Some((desired, desired_count)) = read_longs::<MAX_DESIRED_LONGS>(&env, &desired) else {
        return 0;
    };
    jboolean::from(matches(&current[..count], &desired[..desired_count]).unwrap_or(false))
}

#[no_mangle]
pub extern "system" fn Java_org_wonad_desktop_broker_BrokerNative_nativeTaskAllowed(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    current: JLongArray<'_>,
    token: jlong,
    needs_input: jboolean,
) -> jboolean {
    if needs_input > 1 {
        return 0;
    }
    let Some((current, count)) = read_longs::<MAX_CURRENT_LONGS>(&env, &current) else {
        return 0;
    };
    let Some(current) = decode_snapshot(&current[..count]) else {
        return 0;
    };
    jboolean::from(native_frame::task_allowed(
        &current.snapshot(),
        token,
        needs_input == 1,
    ))
}

fn picker(op: i32, v: &[i64; 7], state: &mut Picker) -> Option<i64> {
    let scope = Scope {
        generation: v[2],
        user: int(v[3])?,
        display_token: v[4],
    };
    let kind = int(v[5])?;
    let value = usize::try_from(v[6]).ok()?;
    Some(match op {
        1 if v[1] == 0 => state.open(scope, kind, value, v[0]).unwrap_or(0),
        2 => i64::from(state.valid(v[1], scope, kind, v[0])),
        3 => i64::from(state.select(v[1], scope, kind, value, v[0])),
        4 => {
            state.cancel(v[1]);
            1
        }
        _ => return None,
    })
}

#[no_mangle]
pub extern "system" fn Java_org_wonad_desktop_broker_BrokerNative_nativePicker(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    operation: jint,
    values: JLongArray<'_>,
) -> jlong {
    let Some((v, 7)) = read_longs::<7>(&env, &values) else {
        return 0;
    };
    let Ok(mut state) = PICKER.lock() else {
        return 0;
    };
    picker(operation, &v, &mut state).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn current() -> Vec<i64> {
        vec![
            42, 9, 2, 1, 1, 100, 2, 0, 0, 1920, 1080, 160, 1, 42, 7, 100, 3, 3, 1917, 1077, 100,
            80, 1, 1, 1, 0,
        ]
    }
    fn desired() -> Vec<i64> {
        vec![
            42, 9, 2, 100, 7, 1, 1, 7, 100, 3, 3, 1917, 1077, 1, 1, 0, 42, 100, 0, 0, 1920, 3,
        ]
    }
    fn frame() -> Vec<i64> {
        vec![
            100, 0, 0, 9, 9, 3, 10152, 0, 1, 0, 0, 0, 0, 0, 0, 2, 1, 0, 1, 100, 2, 0, 0, 1920,
            1080, 160, 1, 0,
        ]
    }

    #[test]
    fn native_bridge_checks_complete_exact_opaque_placements_and_observations() {
        assert_eq!(validate(&current(), &desired()), Some(ResultCode::Applied));
        assert_eq!(matches(&current(), &desired()), Some(true));
        let mut different = desired();
        different[7] = 8;
        assert_eq!(validate(&current(), &different), Some(ResultCode::Invalid));
        assert_eq!(matches(&current(), &different), Some(false));
        let mut different = desired();
        different[16] = 41;
        assert_eq!(validate(&current(), &different), Some(ResultCode::Invalid));
        for (i, value) in [(2, 1), (5, 129), (6, -1), (13, 2), (8, 2)] {
            let mut bad = desired();
            bad[i] = value;
            assert_ne!(validate(&current(), &bad), Some(ResultCode::Applied));
        }
    }

    #[test]
    fn signed_bridge_uses_same_lossless_rows_without_extending_old_desired_geometry() {
        let current = current();
        for bounds in [
            [-100, -50, 918, 712],
            [2000, 2000, 3018, 2762],
            [-2000, -2000, -982, -1238],
        ] {
            let mut desired = desired();
            desired[9..13].copy_from_slice(&bounds);
            assert_eq!(
                validate_signed(&current, &desired),
                Some(ResultCode::Applied)
            );
            assert_eq!(validate(&current, &desired), Some(ResultCode::Invalid));
            assert_eq!(matches(&current, &desired), Some(false));
            let mut applied = current.clone();
            applied[16..20].copy_from_slice(&bounds);
            assert_eq!(matches(&applied, &desired), Some(true));
            assert_eq!(
                validate(&applied, &self::desired()),
                Some(ResultCode::Applied)
            );
        }
    }

    #[test]
    fn signed_bridge_rejects_lossy_edges_and_monitor_region_expansion() {
        for bounds in [
            [i64::MIN, 0, i64::MAX, 100],
            [-32769, 0, 0, 100],
            [-32768, 0, 32768, 100],
            [0, 0, 100, 0],
        ] {
            let mut desired = desired();
            desired[9..13].copy_from_slice(&bounds);
            assert_ne!(
                validate_signed(&current(), &desired),
                Some(ResultCode::Applied)
            );
            let mut observed = current();
            observed[16..20].copy_from_slice(&bounds);
            assert_ne!(
                validate_signed(&observed, &self::desired()),
                Some(ResultCode::Applied)
            );
        }
        for (index, value) in [
            (18, -1),
            (20, 1921),
            (16, 41),
            (17, 0),
            (8, 2),
            (13, 0),
            (15, -1),
        ] {
            let mut desired = desired();
            desired[index] = value;
            assert_eq!(
                validate_signed(&current(), &desired),
                Some(ResultCode::Invalid)
            );
        }
        for length in 0..=100 {
            assert_ne!(
                validate_signed(&vec![0; length], &vec![0; length]),
                Some(ResultCode::Applied)
            );
        }
    }

    #[test]
    fn native_session_supports_only_three_and_reconciles_exact_incarnation_reuse() {
        let mut authority = Authority::new(PACKAGE, [0; 32], 42).unwrap();
        let mut v = frame();
        v[5] = 2;
        assert_eq!(session(1, &v, &mut authority), Some(-2));
        v[5] = 3;
        assert_eq!(session(1, &v, &mut authority), Some(42));
        v[1] = 42;
        v[2] = 1;
        assert_eq!(session(4, &v, &mut authority), Some(0));
        v[19] = 101;
        assert_eq!(
            session(8, &v, &mut authority),
            Some(ResultCode::Stale as i64)
        );
        v[15] = 3;
        assert_eq!(session(2, &v, &mut authority), Some(0));
        assert_eq!(session(5, &v, &mut authority), Some(0));
        v[2] = 2;
        assert_eq!(session(4, &v, &mut authority), Some(0));
        assert_eq!(session(5, &v, &mut authority), Some(1));
        v[15] = 4;
        v[18] = 0;
        v.truncate(19);
        assert_eq!(session(2, &v, &mut authority), Some(2));
        assert_eq!(session(4, &v, &mut authority), Some(4));
    }

    #[test]
    fn malformed_native_auth_scalar_frames_fail_closed_before_slice_arithmetic() {
        let mut authority = Authority::new(PACKAGE, [0; 32], 42).unwrap();
        for length in 0..=SESSION_MAX + 1 {
            assert_ne!(session(1, &vec![0; length], &mut authority), Some(42));
        }
        for (index, value) in [
            (18, -1),
            (18, i64::MAX),
            (18, 10),
            (26, 2),
            (20, i64::MAX),
            (16, 2),
        ] {
            let mut bad = frame();
            bad[index] = value;
            assert_eq!(session(1, &bad, &mut authority), None);
        }
        for length in 0..=100 {
            assert_ne!(
                validate(&vec![0; length], &vec![0; length]),
                Some(ResultCode::Applied)
            );
            assert_ne!(matches(&vec![0; length], &vec![0; length]), Some(true));
        }
    }

    #[test]
    fn native_picker_private_scalars_never_contain_workspace_and_are_one_shot() {
        let mut state = Picker::new();
        let mut v = [100, 0, 42, 0, 100, 1, 5];
        let ticket = picker(1, &v, &mut state).unwrap();
        assert!(ticket > 0);
        v[1] = ticket;
        v[6] = 3;
        assert_eq!(picker(2, &v, &mut state), Some(1));
        assert_eq!(picker(3, &v, &mut state), Some(1));
        assert_eq!(picker(3, &v, &mut state), Some(0));
        v[0] = 1100;
        v[1] = 0;
        v[1] = picker(1, &v, &mut state).unwrap();
        v[4] = 101;
        assert_eq!(picker(2, &v, &mut state), Some(0));
        v[4] = 100;
        assert_eq!(picker(3, &v, &mut state), Some(0));
    }

    #[test]
    fn protocol_three_generation_exhausts_without_wrap() {
        let caller = Caller {
            uid: 10152,
            user_id: 0,
            package_name: PACKAGE,
            signer_sha256: [0; 32],
            shared_uid: false,
        };
        let display = Display {
            token: 100,
            display_id: 2,
            bounds: EMPTY_RECT,
            density_dpi: 160,
            secure: true,
            shell_generation: 0,
        };
        let bounds = super::super::Rect {
            left: 0,
            top: 0,
            right: 1920,
            bottom: 1080,
        };
        let displays = [Display {
            bounds,
            ..display
        }];
        let state = Environment {
            active_user_id: 0,
            user_enabled: true,
            locked: false,
            topology: Topology {
                revision: 1,
                displays: &displays,
            },
        };
        let mut exhausted = Authority::new(PACKAGE, [0; 32], i64::MAX - 1).unwrap();
        let lease = exhausted.open(&caller, &state, 3, 100).unwrap();
        assert_eq!(i64::MAX - 1, lease.generation);
        assert!(exhausted.release(&caller, lease.generation, 100));
        assert_eq!(
            exhausted.open(&caller, &state, 3, 101),
            Err(OpenError::Exhausted)
        );
        assert!(Authority::new(PACKAGE, [0; 32], 0).is_err());
    }
}
