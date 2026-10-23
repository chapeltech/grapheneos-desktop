use wonad_broker_core::layout::Rect;
use wonad_broker_core::native_frame::Display;
use wonad_broker_core::native_shell::*;
const OWNER: Owner = Owner {
    generation: 42,
    uid: 10152,
    user: 0,
};
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
const WINDOW: Observation = Observation {
    display_token: 100,
    native_window_incarnation: 77,
    owner: OWNER,
    fixed_component: true,
    secure: true,
    nonfocusable: true,
    drawn: false,
};

#[test]
fn only_actual_fixed_secure_nonfocusable_drawn_ordinary_apk_window_is_ready() {
    let mut registry = Registrations::new();
    for window in [
        Observation {
            fixed_component: false,
            ..WINDOW
        },
        Observation {
            secure: false,
            ..WINDOW
        },
        Observation {
            nonfocusable: false,
            ..WINDOW
        },
        Observation {
            display_token: 101,
            ..WINDOW
        },
        Observation {
            native_window_incarnation: 0,
            ..WINDOW
        },
        Observation {
            owner: Owner { uid: 1000, ..OWNER },
            ..WINDOW
        },
    ] {
        assert!(!registry.observe(OWNER, DISPLAY, window));
        assert_eq!(registry.ready_generation(100, OWNER), 0);
    }
    assert!(!registry.observe(
        OWNER,
        Display {
            display_id: 0,
            ..DISPLAY
        },
        WINDOW
    ));
    assert!(registry.observe(OWNER, DISPLAY, WINDOW));
    assert_eq!(registry.ready_generation(100, OWNER), 0);
    assert!(registry.observe(
        OWNER,
        DISPLAY,
        Observation {
            drawn: true,
            ..WINDOW
        }
    ));
    assert_eq!(registry.ready_generation(100, OWNER), 42);
}

#[test]
fn old_window_callback_cannot_register_or_remove_new_native_window() {
    let mut registry = Registrations::new();
    assert!(registry.observe(
        OWNER,
        DISPLAY,
        Observation {
            drawn: true,
            ..WINDOW
        }
    ));
    let replacement = Observation {
        native_window_incarnation: 78,
        drawn: true,
        ..WINDOW
    };
    assert!(!registry.observe(OWNER, DISPLAY, replacement));
    assert!(!registry.remove_window(100, 78));
    assert!(registry.remove_window(100, 77));
    assert!(registry.observe(OWNER, DISPLAY, replacement));
    assert!(!registry.remove_window(100, 77));
    assert!(!registry.observe(OWNER, DISPLAY, WINDOW));
    assert_eq!(registry.ready_generation(100, OWNER), 42);
}

#[test]
fn native_display_replacement_and_session_revocation_never_reuse_registration() {
    let mut registry = Registrations::new();
    assert!(registry.observe(
        OWNER,
        DISPLAY,
        Observation {
            drawn: true,
            ..WINDOW
        }
    ));
    assert_eq!(registry.ready_generation(101, OWNER), 0);
    assert!(!registry.detach(101));
    assert!(registry.detach(100));
    let replacement = Display {
        token: 101,
        ..DISPLAY
    };
    assert!(!registry.observe(OWNER, replacement, WINDOW));
    let next = Owner {
        generation: 43,
        ..OWNER
    };
    let new_window = Observation {
        owner: next,
        display_token: 101,
        drawn: true,
        ..WINDOW
    };
    assert!(registry.observe(next, replacement, new_window));
    registry.revoke(42);
    assert_eq!(registry.ready_generation(101, next), 43);
    assert_eq!(registry.ready_generation(101, OWNER), 0);
    registry.revoke(43);
    assert_eq!(registry.ready_generation(101, next), 0);
}
