//! Workspace-free, one-shot v3 picker scope. Scope fields and choice catalogue
//! come only from the OS, never from client-supplied Intent/task/display IDs.
const MAX_CHOICES: usize = 4096;
const TIMEOUT_MILLIS: i64 = 30_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Scope {
    pub generation: i64,
    pub user: i32,
    pub display_token: i64,
}

#[derive(Clone, Copy)]
struct Consent {
    id: i64,
    scope: Scope,
    kind: i32,
    choices: usize,
    deadline: i64,
}

pub struct Picker {
    next: i64,
    last_now: i64,
    next_open: i64,
    consent: Option<Consent>,
}

impl Default for Picker {
    fn default() -> Self {
        Self::new()
    }
}

impl Picker {
    pub const fn new() -> Self {
        Self {
            next: 1,
            last_now: 0,
            next_open: 0,
            consent: None,
        }
    }

    fn clock(&mut self, now: i64) -> bool {
        if now < 0 || now < self.last_now {
            self.consent = None;
            return false;
        }
        self.last_now = now;
        if self.consent.is_some_and(|c| now >= c.deadline) {
            self.consent = None;
        }
        true
    }

    pub fn open(&mut self, scope: Scope, kind: i32, choices: usize, now: i64) -> Option<i64> {
        if !self.clock(now)
            || self.consent.is_some()
            || now < self.next_open
            || scope.generation <= 0
            || scope.user < 0
            || scope.display_token <= 0
            || !(1..=2).contains(&kind)
            || choices > MAX_CHOICES
            || self.next == i64::MAX
        {
            return None;
        }
        let deadline = now.checked_add(TIMEOUT_MILLIS)?;
        let id = self.next;
        self.next += 1;
        self.next_open = now.checked_add(1_000)?;
        self.consent = Some(Consent {
            id,
            scope,
            kind,
            choices,
            deadline,
        });
        Some(id)
    }

    pub fn valid(&mut self, id: i64, scope: Scope, kind: i32, now: i64) -> bool {
        if !self.clock(now) {
            return false;
        }
        let Some(c) = self.consent else {
            return false;
        };
        if c.id != id {
            return false;
        }
        if c.scope != scope || c.kind != kind {
            self.consent = None;
            return false;
        }
        true
    }

    pub fn select(&mut self, id: i64, scope: Scope, kind: i32, index: usize, now: i64) -> bool {
        if !self.valid(id, scope, kind, now) {
            return false;
        }
        self.consent.take().is_some_and(|c| index < c.choices)
    }

    pub fn cancel(&mut self, id: i64) {
        if self.consent.is_some_and(|c| c.id == id) {
            self.consent = None;
        }
    }
}
