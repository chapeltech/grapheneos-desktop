//! Fixed desktop commands, never a raw input stream or configurable global grab.
//! All environment values and the monotonic clock come from system_server.
//! Consumed key pairs are bounded and survive revocation only to drain releases.
use crate::CLIENT_TIMEOUT_MILLIS;

pub const PREFIX: i32 = 0x1000 | 0x10000; // Android CTRL_ON | META_ON.
pub const SHIFT: i32 = 1;
pub const MAX_PRESSED: usize = 16;
pub const KEYSET_VERSION: i32 = 1;
pub const COMMAND_SHORTCUT_KEY: i32 = 17;
pub const PROFILE_PREFIX: i32 = if cfg!(feature = "pixel10-shortcuts") {
    0x10000
} else {
    PREFIX
};

/// A finite control-key alphabet, not application text or a general key grab.
/// The argument is (Android keycode << 1) | shifted. Modifiers/timestamps and
/// releases never cross the APK interface. These numbers are SDK 3.1.0 wire.
pub fn shortcut_argument(code: i32, shifted: bool) -> Option<i32> {
    let allowed = match code {
        8..=16 | 33 | 38 | 39 | 46 | 51 | 62 | 66 | 70 | 76 => true,
        36 | 40 | 42 | 47 | 69 => !shifted, // H/L/N/S/minus.
        31 | 74 => shifted,                 // Shift+C / Shift+semicolon.
        _ => false,
    };
    allowed.then_some((code << 1) | i32::from(shifted))
}

pub fn valid_shortcut_argument(argument: i32) -> bool {
    argument >= 0 && shortcut_argument(argument >> 1, argument & 1 != 0) == Some(argument)
}

pub fn key_command(code: i32, modifiers: i32, prefix: i32) -> Option<Command> {
    if !matches!(prefix, PREFIX | 0x10000) || (modifiers != prefix && modifiers != prefix | SHIFT) {
        return None;
    }
    Some(Command {
        kind: COMMAND_SHORTCUT_KEY,
        argument: shortcut_argument(code, modifiers & SHIFT != 0)?,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Command {
    pub kind: i32,
    pub argument: i32,
}

/// The adapter supplies normalized, non-directional Android modifier bits.
/// Super+Ctrl avoids changing Android's ordinary Super+Home/Lock shortcuts.
pub fn command(code: i32, modifiers: i32) -> Option<Command> {
    if modifiers != PREFIX && modifiers != PREFIX | SHIFT {
        return None;
    }
    let shifted = modifiers & SHIFT != 0;
    if (8..=16).contains(&code) {
        // Android KEYCODE_1 through KEYCODE_9.
        return Some(Command {
            kind: if shifted { 9 } else { 8 },
            argument: code - 7,
        });
    }
    if let Some(argument) = [51, 33, 46].iter().position(|candidate| *candidate == code) {
        // W/E/R: focus or send to the first three external monitors.
        return Some(Command {
            kind: if shifted { 16 } else { 15 },
            argument: argument as i32,
        });
    }
    let kind = match (code, shifted) {
        (38, false) => 1,  // J: focus next.
        (39, false) => 2,  // K: focus previous.
        (38, true) => 3,   // Shift+J: swap next.
        (39, true) => 4,   // Shift+K: swap previous.
        (36, false) => 5,  // H: shrink master.
        (40, false) => 6,  // L: expand master.
        (62, false) => 7,  // Space: cycle layout.
        (31, true) => 10,  // Shift+C: close.
        (48, false) => 11, // T: sink.
        (66, false) => 12, // Enter: system app picker.
        (34, false) => 13, // F: toggle floating.
        (66, true) => 14,  // Shift+Enter: system phone-task transfer picker.
        _ => return None,
    };
    Some(Command { kind, argument: 0 })
}

/// Only these fixed desktop keys may be checked before Android's stock Meta
/// gestures. This does not grant a lease or capture an event; `Input::event`
/// still checks the complete trusted environment and drains exact key pairs.
pub fn command_key(code: i32) -> bool {
    command(code, PREFIX).is_some()
        || command(code, PREFIX | SHIFT).is_some()
        || shortcut_argument(code, false).is_some()
        || shortcut_argument(code, true).is_some()
}

#[cfg(test)]
mod priority_tests {
    use super::*;

    #[test]
    fn priority_is_exactly_the_fixed_desktop_alphabet_not_system_keys() {
        let letters = [
            31, 33, 34, 36, 38, 39, 40, 42, 46, 47, 48, 51, 62, 66, 69, 70, 74, 76,
        ];
        for code in -1..=400 {
            assert_eq!(
                command_key(code),
                (8..=16).contains(&code) || letters.contains(&code)
            );
        }
        for code in [i32::MIN, i32::MAX] {
            assert!(!command_key(code));
        }
    }

    #[test]
    fn priority_does_not_make_plain_or_foreign_modifier_keys_commands() {
        for code in 0..=400 {
            for modifiers in [0, SHIFT, 2, 4, PREFIX | 2, PREFIX | 4, PREFIX | 8] {
                assert_eq!(command(code, modifiers), None);
            }
        }
        assert_eq!(
            command(51, PREFIX),
            Some(Command {
                kind: 15,
                argument: 0
            })
        );
        assert_eq!(
            command(51, PREFIX | SHIFT),
            Some(Command {
                kind: 16,
                argument: 0
            })
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lease {
    pub generation: i64,
    pub user: i32,
    pub display: i32,
    pub expires: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct Environment {
    pub now: i64,
    pub user: i32,
    pub display: i32,
    pub focused_display: i32,
    pub unlocked: bool,
    pub eligible_display: bool,
    pub trusted_event: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct Key {
    pub code: i32,
    pub modifiers: i32,
    pub action: i32, // Android down=0, up=1. Other actions are never claimed.
    pub repeat: i32,
    pub device: i32,
    pub down_time: i64,
    pub cancelled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Press {
    code: i32,
    device: i32,
    down_time: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Pass,
    Consumed,
    Command(Command),
}

pub struct Input {
    lease: Option<Lease>,
    pressed: [Option<Press>; MAX_PRESSED],
    last_now: i64,
    shortcut_keys: bool,
}

impl Default for Input {
    fn default() -> Self {
        Self::new()
    }
}

impl Input {
    pub const fn new() -> Self {
        Self {
            lease: None,
            pressed: [None; MAX_PRESSED],
            last_now: 0,
            shortcut_keys: false,
        }
    }

    fn clock(&mut self, now: i64) -> bool {
        if now < self.last_now || now < 0 {
            self.lease = None;
            return false;
        }
        self.last_now = now;
        if self.lease.is_some_and(|lease| now >= lease.expires) {
            self.lease = None;
        }
        true
    }

    /// Renew only the same live generation/user/display. A new owner must first
    /// revoke or expire the old lease. Its actual Binder lifetime stays in Kotlin.
    pub fn renew(&mut self, next: Lease, now: i64) -> bool {
        if !self.clock(now)
            || next.generation <= 0
            || next.user < 0
            || next.display <= 0
            || !next
                .expires
                .checked_sub(now)
                .is_some_and(|v| (1..=CLIENT_TIMEOUT_MILLIS).contains(&v))
        {
            return false;
        }
        if self.lease.is_some_and(|old| {
            old.generation != next.generation
                || old.user != next.user
                || old.display != next.display
                || next.expires < old.expires
        }) {
            return false;
        }
        self.lease = Some(next);
        self.shortcut_keys = false;
        true
    }

    pub fn renew_keys(&mut self, next: Lease, now: i64) -> bool {
        if !self.renew(next, now) {
            return false;
        }
        self.shortcut_keys = true;
        true
    }

    /// A delayed callback for an old Binder must not revoke its successor.
    pub fn release(&mut self, generation: i64) -> bool {
        if self
            .lease
            .is_some_and(|lease| lease.generation == generation)
        {
            self.lease = None;
            true
        } else {
            false
        }
    }

    pub fn event(&mut self, env: Environment, key: Key) -> Outcome {
        let clock_valid = self.clock(env.now);
        if !env.trusted_event
            || !matches!(key.action, 0 | 1)
            || key.repeat < 0
            || key.down_time < 0
            || key.device < -1
        {
            return Outcome::Pass;
        }
        let press = Press {
            code: key.code,
            device: key.device,
            down_time: key.down_time,
        };
        if let Some(index) = self.pressed.iter().position(|p| *p == Some(press)) {
            // Even if focus/user/lease changed, drain only this exact consumed
            // physical key pair. Never emit a command from repeats or releases.
            if key.action == 1 || key.cancelled {
                self.pressed[index] = None;
            }
            return Outcome::Consumed;
        }
        if key.action != 0
            || key.repeat != 0
            || key.cancelled
            || !clock_valid
            || !env.unlocked
            || !env.eligible_display
            || !env.trusted_event
        {
            return Outcome::Pass;
        }
        let Some(lease) = self.lease else {
            return Outcome::Pass;
        };
        if lease.user != env.user
            || lease.display != env.display
            || lease.display != env.focused_display
        {
            return Outcome::Pass;
        }
        let Some(command) = (if self.shortcut_keys {
            key_command(key.code, key.modifiers, PROFILE_PREFIX)
        } else {
            command(key.code, key.modifiers)
        }) else {
            return Outcome::Pass;
        };
        // Replaced down events from the same physical key cannot fill the table.
        for old in &mut self.pressed {
            if old.is_some_and(|p| p.device == key.device && p.code == key.code) {
                *old = None;
            }
        }
        let Some(slot) = self.pressed.iter_mut().find(|p| p.is_none()) else {
            return Outcome::Pass;
        };
        *slot = Some(press);
        Outcome::Command(command)
    }
}
