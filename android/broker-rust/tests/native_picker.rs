use wonad_broker_core::native_picker::{Picker, Scope};
const SCOPE: Scope = Scope {
    generation: 42,
    user: 0,
    display_token: 100,
};

#[test]
fn native_catalogue_is_bounded_once_and_workspace_free() {
    let mut picker = Picker::new();
    let id = picker.open(SCOPE, 1, 4096, 100).unwrap();
    assert!(picker.valid(id, SCOPE, 1, 101));
    assert!(picker.select(id, SCOPE, 1, 4095, 102));
    assert!(!picker.select(id, SCOPE, 1, 4095, 103));
    assert!(picker.open(SCOPE, 1, 4097, 1100).is_none());
    let empty = picker.open(SCOPE, 1, 0, 1100).unwrap();
    assert!(!picker.select(empty, SCOPE, 1, 0, 1101));
    assert!(!picker.valid(empty, SCOPE, 1, 1102));
}

#[test]
fn old_session_user_and_native_incarnation_cancel_authority() {
    for scope in [
        Scope {
            generation: 43,
            ..SCOPE
        },
        Scope { user: 1, ..SCOPE },
        Scope {
            display_token: 101,
            ..SCOPE
        },
        Scope {
            display_token: 0,
            ..SCOPE
        },
    ] {
        let mut picker = Picker::new();
        let id = picker.open(SCOPE, 1, 5, 100).unwrap();
        assert!(!picker.valid(id, scope, 1, 101));
        assert!(!picker.select(id, SCOPE, 1, 0, 102));
    }
}

#[test]
fn expiry_rollback_wrong_kind_and_invalid_selection_cannot_replay() {
    for (now, kind, index) in [(30100, 1, 0), (99, 1, 0), (101, 2, 0), (101, 1, 5)] {
        let mut picker = Picker::new();
        let id = picker.open(SCOPE, 1, 5, 100).unwrap();
        assert!(!picker.select(id, SCOPE, kind, index, now));
        assert!(!picker.select(id, SCOPE, 1, 0, 30101));
    }
    assert!(Picker::new().open(SCOPE, 1, 1, i64::MAX).is_none());
}
