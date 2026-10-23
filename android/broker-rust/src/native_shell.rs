//! Private OS shell-window registration. Nothing here accepts APK window,
//! surface, component or input handles. The adapter resolves the exact fixed
//! .ExternalShellActivity before constructing an Observation. Registrations
//! cannot survive native display/window replacement or session/user changes.
use crate::native_frame::{Display, MAX_DISPLAYS};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Owner {
    pub generation: i64,
    pub uid: i32,
    pub user: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Observation {
    pub display_token: i64,
    pub native_window_incarnation: i64,
    pub owner: Owner,
    pub fixed_component: bool,
    pub secure: bool,
    pub nonfocusable: bool,
    pub drawn: bool,
}

pub struct Registrations {
    slots: [Option<Observation>; MAX_DISPLAYS],
}

impl Default for Registrations {
    fn default() -> Self {
        Self::new()
    }
}

impl Registrations {
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_DISPLAYS],
        }
    }

    /// Owner and display are authenticated, fresh native OS observations.
    /// A different window requires exact removal of the old registration.
    pub fn observe(&mut self, owner: Owner, display: Display, window: Observation) -> bool {
        if owner.generation <= 0
            || owner.uid < 0
            || owner.user < 0
            || owner.uid / 100_000 != owner.user
            || !(10_000..=19_999).contains(&(owner.uid % 100_000))
            || display.display_id <= 0
            || display.token <= 0
            || !display.bounds.valid()
            || !display.secure
            || window.owner != owner
            || !window.fixed_component
            || !window.secure
            || !window.nonfocusable
            || window.native_window_incarnation <= 0
            || window.display_token != display.token
        {
            return false;
        }
        let index = self
            .slots
            .iter()
            .position(|slot| slot.is_some_and(|old| old.display_token == display.token))
            .or_else(|| self.slots.iter().position(Option::is_none));
        let Some(index) = index else {
            return false;
        };
        if self.slots[index].is_some_and(|old| {
            old.owner != owner || old.native_window_incarnation != window.native_window_incarnation
        }) {
            return false;
        }
        self.slots[index] = Some(window);
        true
    }

    pub fn ready_generation(&self, display_token: i64, owner: Owner) -> i64 {
        self.slots
            .iter()
            .flatten()
            .find(|window| {
                window.display_token == display_token && window.owner == owner && window.drawn
            })
            .map_or(0, |window| window.owner.generation)
    }

    pub fn remove_window(&mut self, display_token: i64, incarnation: i64) -> bool {
        let Some(slot) = self.slots.iter_mut().find(|slot| {
            slot.is_some_and(|window| {
                window.display_token == display_token
                    && window.native_window_incarnation == incarnation
            })
        }) else {
            return false;
        };
        *slot = None;
        true
    }

    /// Native display-removal observer only. Recycled displayId is irrelevant.
    pub fn detach(&mut self, display_token: i64) -> bool {
        let Some(slot) = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_some_and(|window| window.display_token == display_token))
        else {
            return false;
        };
        *slot = None;
        true
    }

    pub fn revoke(&mut self, generation: i64) {
        for slot in &mut self.slots {
            if slot.is_some_and(|window| window.owner.generation == generation) {
                *slot = None;
            }
        }
    }
}
