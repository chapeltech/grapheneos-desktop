//! External-screen UI ownership outlives a client lease. Only physical display
//! removal returns a claimed screen to Android. Platform objects and caller
//! authentication belong to the system_server adapter.
use crate::CLIENT_TIMEOUT_MILLIS;

pub const MAX_DISPLAYS: usize = 9;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Mode {
    Android,
    Wonad,
    Blank,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lease {
    pub display: i32,
    /// OS-generated incarnation, never a recyclable Android display ID alone.
    pub incarnation: i64,
    pub user: i32,
    pub generation: i64,
    pub expires: i64,
}

pub struct Claims {
    slots: [Option<Lease>; MAX_DISPLAYS],
    last_now: i64,
}

impl Default for Claims {
    fn default() -> Self {
        Self::new()
    }
}

impl Claims {
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_DISPLAYS],
            last_now: 0,
        }
    }

    fn clock(&mut self, now: i64) -> bool {
        if now < self.last_now || now < 0 {
            // Fail closed without restoring Android UI on any connected screen.
            for lease in self.slots.iter_mut().flatten() {
                lease.expires = 0;
            }
            return false;
        }
        self.last_now = now;
        true
    }

    /// `authorized` is a fresh OS admission decision, never APK-provided.
    /// The adapter also matches the actual owner Binder for renewals.
    pub fn renew(&mut self, next: Lease, now: i64, authorized: bool) -> bool {
        if !self.clock(now)
            || !authorized
            || next.display <= 0
            || next.incarnation <= 0
            || next.user < 0
            || next.generation <= 0
            || !next
                .expires
                .checked_sub(now)
                .is_some_and(|left| (1..=CLIENT_TIMEOUT_MILLIS).contains(&left))
        {
            return false;
        }
        let index = self
            .slots
            .iter()
            .position(|slot| slot.is_some_and(|old| old.display == next.display))
            .or_else(|| self.slots.iter().position(Option::is_none));
        let Some(index) = index else {
            return false;
        };
        if let Some(old) = self.slots[index] {
            if old.incarnation != next.incarnation
                || (old.expires <= now && old.generation == next.generation)
                || (old.expires > now
                    && (old.generation != next.generation || old.user != next.user))
            {
                return false;
            }
        }
        self.slots[index] = Some(next);
        true
    }

    /// Losing consent, lock/user transitions, timeout and Binder death all leave
    /// a blank Wonad-owned display. A fresh authorized lease can resume it.
    pub fn park(&mut self, display: i32, incarnation: i64, generation: i64) -> bool {
        let Some(old) = self.slots.iter_mut().flatten().find(|old| {
            old.display == display && old.incarnation == incarnation && old.generation == generation
        }) else {
            return false;
        };
        old.expires = 0;
        true
    }

    pub fn mode(
        &mut self,
        display: i32,
        incarnation: i64,
        now: i64,
        eligible: bool,
        active_user: i32,
    ) -> Mode {
        let valid_clock = self.clock(now);
        let Some(old) = self
            .slots
            .iter_mut()
            .flatten()
            .find(|old| old.display == display && old.incarnation == incarnation)
        else {
            return Mode::Android;
        };
        if !valid_clock || !eligible || old.user != active_user || now >= old.expires {
            old.expires = 0;
            Mode::Blank
        } else {
            Mode::Wonad
        }
    }

    /// Called for the exact removed native DisplayContent, not on sleep,
    /// disablement, topology revision, client release, or an observation timeout.
    pub fn detach(&mut self, display: i32, incarnation: i64) -> bool {
        let Some(slot) = self.slots.iter_mut().find(|slot| {
            slot.is_some_and(|old| old.display == display && old.incarnation == incarnation)
        }) else {
            return false;
        };
        *slot = None;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn lease(display: i32) -> Lease {
        Lease {
            display,
            incarnation: i64::from(display),
            user: 0,
            generation: 10,
            expires: 5000,
        }
    }
    #[test]
    fn phone_and_unauthorized_displays_never_claimed() {
        let mut claims = Claims::new();
        assert!(!claims.renew(lease(0), 0, true));
        assert!(!claims.renew(lease(1), 0, false));
        assert_eq!(claims.mode(0, 0, 0, true, 0), Mode::Android);
        assert_eq!(claims.mode(1, 1, 0, true, 0), Mode::Android);
    }
    #[test]
    fn expiry_is_blank_until_new_authorized_lease_or_unplug() {
        let mut claims = Claims::new();
        assert!(claims.renew(lease(1), 0, true));
        assert_eq!(claims.mode(1, 1, 4999, true, 0), Mode::Wonad);
        assert_eq!(claims.mode(1, 1, 5000, true, 0), Mode::Blank);
        assert_eq!(claims.mode(1, 1, 7000, true, 0), Mode::Blank);
        let next = Lease {
            generation: 11,
            expires: 12000,
            ..lease(1)
        };
        assert!(!claims.renew(next, 7000, false));
        assert!(claims.renew(next, 7000, true));
        assert_eq!(claims.mode(1, 1, 7000, true, 0), Mode::Wonad);
        assert!(claims.detach(1, 1));
        assert_eq!(claims.mode(1, 1, 7000, true, 0), Mode::Android);
    }
    #[test]
    fn death_and_explicit_release_do_not_restore_android() {
        let mut claims = Claims::new();
        assert!(claims.renew(lease(1), 0, true));
        assert!(!claims.park(1, 1, 9));
        assert_eq!(claims.mode(1, 1, 1, true, 0), Mode::Wonad);
        assert!(claims.park(1, 1, 10));
        assert_eq!(claims.mode(1, 1, 1, true, 0), Mode::Blank);
        assert!(!claims.renew(lease(1), 1, true));
        assert!(claims.renew(
            Lease {
                generation: 11,
                ..lease(1)
            },
            1,
            true
        ));
    }
    #[test]
    fn display_id_reuse_requires_exact_native_detach() {
        let mut claims = Claims::new();
        assert!(claims.renew(lease(1), 0, true));
        let replacement = Lease {
            incarnation: 100,
            ..lease(1)
        };
        assert!(!claims.renew(replacement, 1, true));
        assert!(!claims.detach(1, 100));
        assert!(claims.detach(1, 1));
        assert!(claims.renew(replacement, 1, true));
        assert!(!claims.park(1, 1, 10));
        assert!(!claims.detach(1, 1));
        assert_eq!(claims.mode(1, 100, 1, true, 0), Mode::Wonad);
    }
    #[test]
    fn protected_transitions_require_a_fresh_lease() {
        for (eligible, user) in [(false, 0), (true, 1)] {
            let mut claims = Claims::new();
            assert!(claims.renew(lease(1), 0, true));
            assert_eq!(claims.mode(1, 1, 1, eligible, user), Mode::Blank);
            assert_eq!(claims.mode(1, 1, 2, true, 0), Mode::Blank);
        }
    }
    #[test]
    fn live_generation_cannot_be_replaced_and_timeout_is_bounded() {
        let mut claims = Claims::new();
        assert!(claims.renew(lease(1), 0, true));
        for next in [
            Lease {
                generation: 11,
                ..lease(1)
            },
            Lease {
                user: 1,
                ..lease(1)
            },
            Lease {
                expires: 5002,
                ..lease(1)
            },
            Lease {
                expires: 1,
                ..lease(1)
            },
        ] {
            assert!(!claims.renew(next, 1, true));
        }
        assert_eq!(claims.mode(1, 1, 1, true, 0), Mode::Wonad);
    }
    #[test]
    fn all_monitors_are_bounded_and_independent() {
        let mut claims = Claims::new();
        for id in 1..=9 {
            assert!(claims.renew(lease(id), 0, true));
        }
        assert!(!claims.renew(lease(10), 0, true));
        assert!(claims.park(4, 4, 10));
        assert!(claims.detach(5, 5));
        assert!(claims.renew(lease(10), 1, true));
        for id in 1..=10 {
            assert_eq!(
                claims.mode(id, i64::from(id), 1, true, 0),
                match id {
                    4 => Mode::Blank,
                    5 => Mode::Android,
                    _ => Mode::Wonad,
                }
            );
        }
    }
    #[test]
    fn clock_rollback_parks_all_claimed_screens() {
        let mut claims = Claims::new();
        assert!(claims.renew(lease(1), 100, true));
        assert!(claims.renew(lease(2), 100, true));
        assert_eq!(claims.mode(1, 1, 99, true, 0), Mode::Blank);
        assert_eq!(claims.mode(2, 2, 100, true, 0), Mode::Blank);
        assert!(!claims.renew(lease(1), 99, true));
    }
}
