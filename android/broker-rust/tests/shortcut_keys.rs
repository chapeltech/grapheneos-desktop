use wonad_broker_core::shortcuts::*;

fn env() -> Environment {
    Environment {
        now: 2,
        user: 0,
        display: 2,
        focused_display: 2,
        unlocked: true,
        eligible_display: true,
        trusted_event: true,
    }
}
fn key(code: i32, modifiers: i32) -> Key {
    Key {
        code,
        modifiers,
        action: 0,
        repeat: 0,
        device: 4,
        down_time: 1,
        cancelled: false,
    }
}
fn lease() -> Lease {
    Lease {
        generation: 10,
        user: 0,
        display: 2,
        expires: 4000,
    }
}

#[test]
fn both_product_prefixes_have_the_same_exact_control_alphabet() {
    for prefix in [PREFIX, 0x10000] {
        for code in -1..401 {
            for shift in [false, true] {
                let command = key_command(code, prefix | if shift { SHIFT } else { 0 }, prefix);
                assert_eq!(
                    command.map(|c| (c.kind, c.argument)),
                    shortcut_argument(code, shift).map(|a| (17, a))
                );
                for extra in [2, 4, 8, 0x100] {
                    assert!(key_command(code, prefix | extra, prefix).is_none());
                }
            }
        }
    }
    assert!(key_command(66, 0x10000, PREFIX).is_none());
    assert!(key_command(66, PREFIX, 0x10000).is_none());
    for bad in [-1, 0, 1, i32::MAX] {
        assert!(!valid_shortcut_argument(bad));
    }
}
#[test]
fn opt_in_does_not_reinterpret_old_commands_and_mode_switch_drains_keys() {
    let mut input = Input::new();
    assert!(input.renew(lease(), 1));
    let k = key(66, PREFIX | SHIFT);
    assert_eq!(
        input.event(env(), k),
        Outcome::Command(Command {
            kind: 14,
            argument: 0
        })
    );
    assert!(input.renew_keys(lease(), 2));
    let mut up = k;
    up.action = 1;
    up.modifiers = 0;
    let mut phone = env();
    phone.display = 0;
    phone.focused_display = 0;
    assert_eq!(input.event(phone, up), Outcome::Consumed);
    assert_eq!(
        input.event(env(), key(66, PROFILE_PREFIX | SHIFT)),
        Outcome::Command(Command {
            kind: 17,
            argument: 133
        })
    );
    assert!(input.release(10));
    let mut release = key(66, 0);
    release.action = 1;
    assert_eq!(input.event(phone, release), Outcome::Consumed);
    assert_eq!(input.event(env(), key(66, PROFILE_PREFIX)), Outcome::Pass);
}
#[test]
fn new_keys_require_the_original_trusted_environment() {
    for fault in 0..5 {
        let mut input = Input::new();
        input.renew_keys(lease(), 1);
        let mut e = env();
        match fault {
            0 => e.trusted_event = false,
            1 => e.unlocked = false,
            2 => e.eligible_display = false,
            3 => e.focused_display = 0,
            _ => e.user = 1,
        }
        assert_eq!(input.event(e, key(76, PROFILE_PREFIX)), Outcome::Pass);
    }
}
