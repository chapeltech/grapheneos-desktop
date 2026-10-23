//! system_server-private scalar bridge. No Binder, Context or KeyEvent retained.
use jni::objects::{JClass, JLongArray};
use jni::sys::{jboolean, jint, jlong};
use jni::JNIEnv;
use std::sync::Mutex;
use wonad_broker_core::external_ui::{Claims, Lease as UiLease, Mode};
use wonad_broker_core::shortcuts::{Environment, Input, Key, Lease, Outcome};

static UI_CLAIMS: Mutex<Claims> = Mutex::new(Claims::new());

#[no_mangle]
pub extern "system" fn Java_org_wonad_server_input_InputNative_commandKey(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    code: jint,
) -> jboolean {
    wonad_broker_core::shortcuts::command_key(code) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_org_wonad_server_input_InputNative_uiRenew(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    display: jint,
    incarnation: jlong,
    user: jint,
    generation: jlong,
    expires: jlong,
    now: jlong,
    authorized: jboolean,
) -> jboolean {
    UI_CLAIMS.lock().ok().is_some_and(|mut claims| {
        claims.renew(
            UiLease {
                display,
                incarnation,
                user,
                generation,
                expires,
            },
            now,
            authorized != 0,
        )
    }) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_org_wonad_server_input_InputNative_uiMode(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    display: jint,
    incarnation: jlong,
    now: jlong,
    eligible: jboolean,
    active_user: jint,
) -> jint {
    // Poisoning must never expose Android UI or revive a client on a claimed display.
    UI_CLAIMS.lock().ok().map_or(2, |mut claims| {
        match claims.mode(display, incarnation, now, eligible != 0, active_user) {
            Mode::Android => 0,
            Mode::Wonad => 1,
            Mode::Blank => 2,
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_org_wonad_server_input_InputNative_uiPark(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    display: jint,
    incarnation: jlong,
    generation: jlong,
) {
    if let Ok(mut claims) = UI_CLAIMS.lock() {
        claims.park(display, incarnation, generation);
    }
}

#[no_mangle]
pub extern "system" fn Java_org_wonad_server_input_InputNative_uiDetach(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    display: jint,
    incarnation: jlong,
) {
    if let Ok(mut claims) = UI_CLAIMS.lock() {
        claims.detach(display, incarnation);
    }
}

struct Slot {
    display: i32,
    generation: i64,
    user: i32,
    expires: i64,
    input: Input,
}
impl Slot {
    const fn new() -> Self {
        Self {
            display: -1,
            generation: 0,
            user: -1,
            expires: 0,
            input: Input::new(),
        }
    }
}

/// Bounded display leases with key-release draining across focus/topology changes.
struct Inputs {
    slots: [Slot; 9],
    last_now: i64,
}
impl Inputs {
    const fn new() -> Self {
        Self {
            slots: [const { Slot::new() }; 9],
            last_now: 0,
        }
    }
    fn clock(&mut self, now: i64) -> bool {
        if now < 0 || now < self.last_now {
            // Each Input keeps captured key pairs to drain, but no monitor may
            // retain authority across a rollback observed on another monitor.
            for slot in &mut self.slots {
                slot.input.release(slot.generation);
                slot.expires = 0;
            }
            return false;
        }
        self.last_now = now;
        true
    }
    fn renew(&mut self, lease: Lease, now: i64) -> bool {
        if !self.clock(now) {
            return false;
        }
        if self
            .slots
            .iter()
            .any(|s| s.expires > now && (s.generation != lease.generation || s.user != lease.user))
        {
            return false;
        }
        let index = self
            .slots
            .iter()
            .position(|s| s.display == lease.display)
            .or_else(|| self.slots.iter().position(|s| s.expires <= now));
        let Some(index) = index else {
            return false;
        };
        let slot = &mut self.slots[index];
        if slot.display != lease.display {
            slot.input.release(slot.generation);
        }
        if !slot.input.renew(lease, now) {
            return false;
        }
        slot.display = lease.display;
        slot.generation = lease.generation;
        slot.user = lease.user;
        slot.expires = lease.expires;
        true
    }
    fn release(&mut self, generation: i64, display: Option<i32>) {
        for slot in &mut self.slots {
            if display.is_none_or(|id| slot.display == id) && slot.generation == generation {
                slot.input.release(generation);
                slot.expires = 0;
            }
        }
    }
    fn renew_keys(&mut self, lease: Lease, now: i64) -> bool {
        if !self.renew(lease, now) { return false; }
        self.slots.iter_mut().find(|s| s.display == lease.display)
            .is_some_and(|s| s.input.renew_keys(lease, now))
    }
    fn event(&mut self, env: Environment, key: Key) -> Outcome {
        let clock_valid = self.clock(env.now);
        // Drain a captured physical key pair before allowing a newly focused
        // display to interpret it. Revocation never transfers a key-up to an app.
        let mut drained = false;
        for slot in &mut self.slots {
            drained |= slot.input.event(
                Environment {
                    eligible_display: false,
                    ..env
                },
                key,
            ) == Outcome::Consumed;
        }
        if drained {
            return Outcome::Consumed;
        }
        if !clock_valid {
            return Outcome::Pass;
        }
        self.slots
            .iter_mut()
            .find(|s| s.display == env.display)
            .map_or(Outcome::Pass, |s| s.input.event(env, key))
    }
}

static INPUT: Mutex<Inputs> = Mutex::new(Inputs::new());

#[no_mangle]
pub extern "system" fn Java_org_wonad_server_input_InputNative_shortcutPrefix(
    _env: JNIEnv<'_>, _class: JClass<'_>,
) -> jint {
    wonad_broker_core::shortcuts::PROFILE_PREFIX
}

#[no_mangle]
pub extern "system" fn Java_org_wonad_server_input_InputNative_renewKeys(
    _env: JNIEnv<'_>, _class: JClass<'_>, generation: jlong, user: jint,
    display: jint, expires: jlong, now: jlong,
) -> jboolean {
    INPUT.lock().ok().is_some_and(|mut input|
        input.renew_keys(Lease { generation, user, display, expires }, now)) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_org_wonad_server_input_InputNative_renew(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    generation: jlong,
    user: jint,
    display: jint,
    expires: jlong,
    now: jlong,
) -> jboolean {
    INPUT.lock().ok().is_some_and(|mut input| {
        input.renew(
            Lease {
                generation,
                user,
                display,
                expires,
            },
            now,
        )
    }) as jboolean
}

#[no_mangle]
pub extern "system" fn Java_org_wonad_server_input_InputNative_release(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    generation: jlong,
) {
    if let Ok(mut input) = INPUT.lock() {
        input.release(generation, None);
    }
}

#[no_mangle]
pub extern "system" fn Java_org_wonad_server_input_InputNative_releaseDisplay(
    _env: JNIEnv<'_>,
    _class: JClass<'_>,
    generation: jlong,
    display: jint,
) {
    if let Ok(mut input) = INPUT.lock() {
        input.release(generation, Some(display));
    }
}

fn boolean(value: i64) -> Option<bool> {
    match value {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

fn decode(v: &[i64; 14]) -> Option<(Environment, Key)> {
    Some((
        Environment {
            now: v[0],
            user: v[1].try_into().ok()?,
            display: v[2].try_into().ok()?,
            focused_display: v[3].try_into().ok()?,
            unlocked: boolean(v[4])?,
            eligible_display: boolean(v[5])?,
            trusted_event: boolean(v[6])?,
        },
        Key {
            code: v[7].try_into().ok()?,
            modifiers: v[8].try_into().ok()?,
            action: v[9].try_into().ok()?,
            repeat: v[10].try_into().ok()?,
            device: v[11].try_into().ok()?,
            down_time: v[12],
            cancelled: boolean(v[13])?,
        },
    ))
}

#[no_mangle]
pub extern "system" fn Java_org_wonad_server_input_InputNative_event(
    env: JNIEnv<'_>,
    _class: JClass<'_>,
    values: JLongArray<'_>,
) -> jlong {
    if env.get_array_length(&values).ok() != Some(14) {
        return 0;
    }
    let mut v = [0; 14];
    if env.get_long_array_region(&values, 0, &mut v).is_err() {
        return 0;
    }
    let Some((environment, key)) = decode(&v) else {
        return 0;
    };
    let Ok(mut input) = INPUT.lock() else {
        return 0;
    };
    match input.event(environment, key) {
        Outcome::Pass => 0,
        Outcome::Consumed => -1,
        Outcome::Command(command) => (i64::from(command.kind) << 32) | i64::from(command.argument),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn backwards_clock_across_different_monitor_renewals_never_admits_a_key() {
        let mut input = Inputs::new();
        assert!(input.renew(
            Lease {
                generation: 1,
                user: 0,
                display: 2,
                expires: 500
            },
            200
        ));
        assert!(!input.renew(
            Lease {
                generation: 1,
                user: 0,
                display: 3,
                expires: 500
            },
            100
        ));
        let (env, key) = decode(&[150, 0, 3, 3, 1, 1, 1, 38, 0x11000, 0, 0, 3, 50, 0]).unwrap();
        assert_eq!(input.event(env, key), Outcome::Pass);
    }
    #[test]
    fn rollback_revokes_every_monitor_but_still_drains_captured_key_up() {
        let mut input = Inputs::new();
        for display in [2, 3] {
            assert!(input.renew(
                Lease {
                    generation: 1,
                    user: 0,
                    display,
                    expires: 500
                },
                100
            ));
        }
        let (mut env, mut key) =
            decode(&[100, 0, 2, 2, 1, 1, 1, 38, 0x11000, 0, 0, 3, 50, 0]).unwrap();
        assert!(matches!(input.event(env, key), Outcome::Command(_)));
        env.now = 90;
        env.display = 3;
        env.focused_display = 3;
        key.action = 1;
        assert_eq!(input.event(env, key), Outcome::Consumed);
        env.now = 101;
        key.action = 0;
        key.down_time = 100;
        assert_eq!(input.event(env, key), Outcome::Pass);
        assert!(input.renew(
            Lease {
                generation: 2,
                user: 0,
                display: 3,
                expires: 500
            },
            102
        ));
        env.now = 102;
        assert!(matches!(input.event(env, key), Outcome::Command(_)));
    }
    #[test]
    fn reused_slot_retains_old_captured_release_without_authorizing_old_display() {
        let mut input = Inputs::new();
        assert!(input.renew(
            Lease {
                generation: 1,
                user: 0,
                display: 2,
                expires: 500
            },
            100
        ));
        let (mut env, mut key) =
            decode(&[100, 0, 2, 2, 1, 1, 1, 38, 0x11000, 0, 0, 3, 50, 0]).unwrap();
        assert!(matches!(input.event(env, key), Outcome::Command(_)));
        input.release(1, Some(2));
        assert!(input.renew(
            Lease {
                generation: 2,
                user: 0,
                display: 3,
                expires: 500
            },
            101
        ));
        input.release(1, None); // An old Binder callback must not clear the new owner.
        env.now = 102;
        env.display = 3;
        env.focused_display = 3;
        key.action = 1;
        assert_eq!(input.event(env, key), Outcome::Consumed);
        key.action = 0;
        key.down_time = 100;
        assert!(matches!(input.event(env, key), Outcome::Command(_)));
        key.down_time = 101;
        env.display = 2;
        env.focused_display = 2;
        assert_eq!(input.event(env, key), Outcome::Pass);
    }
    #[test]
    fn unrelated_untrusted_keys_never_drain_captured_pairs_or_invoke_commands() {
        let mut input = Inputs::new();
        for display in [2, 3] {
            assert!(input.renew(
                Lease {
                    generation: 1,
                    user: 0,
                    display,
                    expires: 500
                },
                100
            ));
        }
        let (mut env, mut key) =
            decode(&[100, 0, 2, 2, 1, 1, 1, 51, 0x11000, 0, 0, 3, 50, 0]).unwrap();
        assert!(matches!(input.event(env, key), Outcome::Command(_)));
        env.display = 3;
        env.focused_display = 3;
        key.action = 1;
        assert_eq!(
            input.event(
                Environment {
                    trusted_event: false,
                    ..env
                },
                key
            ),
            Outcome::Pass
        );
        assert_eq!(input.event(env, Key { device: 4, ..key }), Outcome::Pass);
        assert_eq!(input.event(env, key), Outcome::Consumed);
        key.action = 0;
        key.down_time = 100;
        assert_eq!(
            input.event(
                Environment {
                    focused_display: 0,
                    ..env
                },
                key
            ),
            Outcome::Pass
        );
    }
    #[test]
    fn display_leases_route_and_drain_without_cross_display_authority() {
        let mut input = Inputs::new();
        for display in [2, 3] {
            assert!(input.renew(
                Lease {
                    generation: 1,
                    user: 0,
                    display,
                    expires: 500,
                },
                100
            ));
        }
        assert!(!input.renew(
            Lease {
                generation: 2,
                user: 0,
                display: 4,
                expires: 500
            },
            100
        ));
        let (mut env, mut key) =
            decode(&[100, 0, 2, 2, 1, 1, 1, 38, 0x11000, 0, 0, 3, 50, 0]).unwrap();
        assert!(matches!(input.event(env, key), Outcome::Command(_)));
        input.release(1, Some(2));
        env.display = 3;
        env.focused_display = 3;
        key.action = 1;
        assert_eq!(input.event(env, key), Outcome::Consumed);
        key.action = 0;
        key.down_time = 90;
        assert!(matches!(input.event(env, key), Outcome::Command(_)));
        env.display = 0;
        env.focused_display = 0;
        key.down_time = 95;
        assert_eq!(input.event(env, key), Outcome::Pass);
    }
    #[test]
    fn capacity_is_bounded_but_expired_slots_can_be_reused() {
        let mut input = Inputs::new();
        for display in 1..=9 {
            assert!(input.renew(
                Lease {
                    generation: 1,
                    user: 0,
                    display,
                    expires: 500
                },
                100
            ));
        }
        assert!(!input.renew(
            Lease {
                generation: 1,
                user: 0,
                display: 10,
                expires: 500
            },
            100
        ));
        input.release(1, Some(4));
        assert!(input.renew(
            Lease {
                generation: 1,
                user: 0,
                display: 10,
                expires: 500
            },
            100
        ));
    }
    #[test]
    fn malformed_scalars_are_not_truncated_to_valid_keys_or_environment() {
        let valid = [100, 0, 2, 2, 1, 1, 1, 38, 0x11000, 0, 0, 3, 50, 0];
        assert!(decode(&valid).is_some());
        for index in [1, 2, 3, 7, 8, 9, 10, 11] {
            for value in [i64::MIN, i64::MAX] {
                let mut values = valid;
                values[index] = value;
                assert!(decode(&values).is_none());
            }
        }
        for index in [4, 5, 6, 13] {
            for value in [-1, 2, 256] {
                let mut values = valid;
                values[index] = value;
                assert!(decode(&values).is_none());
            }
        }
    }
}
