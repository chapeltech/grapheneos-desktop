//! Protocol-v3 authority has no workspace/desk dependencies. Fresh OS identity
//! and topology observations are required on every call. The adapter must
//! blank/recover native WM/input on revocation; this pure core cannot do that.
use crate::authority::{Admission, Caller, IdentityCheck, OpenError, Revocation};
use crate::layout::Rect;
use crate::native_frame::{self, Display, Topology, API_VERSION, MAX_DISPLAYS};
use crate::{ResultCode, CLIENT_TIMEOUT_MILLIS};

#[derive(Clone, Copy, Debug)]
pub struct Environment<'a> {
    pub active_user_id: i32,
    pub user_enabled: bool,
    pub locked: bool,
    pub topology: Topology<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lease {
    pub generation: i64,
    pub uid: i32,
    pub user_id: i32,
}

#[derive(Clone, Copy, Debug)]
pub struct Request {
    pub request_id: i64,
    pub base_revision: i64,
    pub actual_revision: i64,
    pub topology_revision: i64,
}

const EMPTY_DISPLAY: Display = Display {
    token: 0,
    display_id: 0,
    bounds: Rect {
        left: 0,
        top: 0,
        right: 0,
        bottom: 0,
    },
    density_dpi: 0,
    secure: false,
    shell_generation: 0,
};

pub struct Authority<'a> {
    // Reuse the precise package/signer/UID predicate for the sole v3 lease.
    identity: IdentityCheck<'a>,
    next_generation: i64,
    generation_stride: i64,
    lease: Option<Lease>,
    displays: [Display; MAX_DISPLAYS],
    display_count: usize,
    topology_revision: i64,
    heartbeat_time: i64,
    heartbeat_sequence: i64,
    request_sequence: i64,
    pending_request: Option<i64>,
}

impl<'a> Authority<'a> {
    pub fn new(package: &'a str, signer: [u8; 32], seed: i64) -> Result<Self, OpenError> {
        Self::new_with_stride(package, signer, seed, 1)
    }

    pub fn new_with_stride(
        package: &'a str,
        signer: [u8; 32],
        seed: i64,
        stride: i64,
    ) -> Result<Self, OpenError> {
        if seed <= 0 || seed == i64::MAX || stride <= 0 {
            return Err(OpenError::InvalidConfiguration);
        }
        Ok(Self {
            identity: IdentityCheck::new(package, signer)?,
            next_generation: seed,
            generation_stride: stride,
            lease: None,
            displays: [EMPTY_DISPLAY; MAX_DISPLAYS],
            display_count: 0,
            topology_revision: -1,
            heartbeat_time: 0,
            heartbeat_sequence: 0,
            request_sequence: 0,
            pending_request: None,
        })
    }

    pub fn allowed(&self, caller: &Caller<'_>, active_user: i32) -> bool {
        self.identity.allowed(caller, active_user)
    }

    pub fn topology(&self) -> Option<Topology<'_>> {
        self.lease.map(|_| Topology {
            revision: self.topology_revision,
            displays: &self.displays[..self.display_count],
        })
    }

    pub fn open(
        &mut self,
        caller: &Caller<'_>,
        state: &Environment<'_>,
        version: i32,
        now: i64,
    ) -> Result<Lease, OpenError> {
        if !self.allowed(caller, state.active_user_id)
            || !state.user_enabled
            || state.locked
            || !native_frame::validate_topology(&state.topology)
            || now < 0
        {
            return Err(OpenError::Unauthorized);
        }
        if version != API_VERSION {
            return Err(OpenError::UnsupportedVersion);
        }
        if self.lease.is_some() {
            return Err(OpenError::AlreadyOpen);
        }
        let Some(next_generation) = self.next_generation.checked_add(self.generation_stride) else {
            return Err(OpenError::Exhausted);
        };
        let lease = Lease {
            generation: self.next_generation,
            uid: caller.uid,
            user_id: caller.user_id,
        };
        self.next_generation = next_generation;
        self.lease = Some(lease);
        self.install_topology(&state.topology);
        self.heartbeat_time = now;
        self.heartbeat_sequence = 0;
        self.request_sequence = 0;
        self.pending_request = None;
        Ok(lease)
    }

    pub fn reconcile(
        &mut self,
        state: &Environment<'_>,
        owner_now: Option<&Caller<'_>>,
        now: i64,
    ) -> Option<Revocation> {
        let lease = self.lease?;
        let reason = if state.active_user_id != lease.user_id {
            Revocation::UserChanged
        } else if !state.user_enabled {
            Revocation::Disabled
        } else if state.locked {
            Revocation::Locked
        } else if !owner_now.is_some_and(|c| self.allowed(c, lease.user_id) && c.uid == lease.uid) {
            Revocation::IdentityChanged
        } else if !self.live_at(now) {
            Revocation::ClientFailed
        } else if self.sync_topology(&state.topology) != ResultCode::Applied {
            Revocation::Undocked
        } else {
            return None;
        };
        self.clear();
        Some(reason)
    }

    pub fn update_topology(
        &mut self,
        caller: &Caller<'_>,
        generation: i64,
        observed: &Topology<'_>,
        now: i64,
    ) -> ResultCode {
        if !self.owns(caller, generation, now) {
            return ResultCode::Revoked;
        }
        self.sync_topology(observed)
    }

    fn sync_topology(&mut self, observed: &Topology<'_>) -> ResultCode {
        if !native_frame::validate_topology(observed) {
            return ResultCode::Invalid;
        }
        let same = observed.displays.len() == self.display_count
            && observed
                .displays
                .iter()
                .all(|display| self.displays[..self.display_count].contains(display));
        if observed.revision < self.topology_revision
            || (observed.revision == self.topology_revision && !same)
        {
            return ResultCode::Stale;
        }
        if observed.revision != self.topology_revision {
            self.install_topology(observed);
            // A callback for removed native objects cannot certify new ones.
            self.pending_request = None;
        }
        ResultCode::Applied
    }

    fn install_topology(&mut self, observed: &Topology<'_>) {
        self.displays = [EMPTY_DISPLAY; MAX_DISPLAYS];
        self.display_count = observed.displays.len();
        self.displays[..self.display_count].copy_from_slice(observed.displays);
        self.topology_revision = observed.revision;
    }

    fn live_at(&self, now: i64) -> bool {
        now.checked_sub(self.heartbeat_time)
            .is_some_and(|elapsed| (0..CLIENT_TIMEOUT_MILLIS).contains(&elapsed))
    }

    pub fn owns(&self, caller: &Caller<'_>, generation: i64, now: i64) -> bool {
        self.lease.is_some_and(|lease| {
            lease.generation == generation
                && self.allowed(caller, lease.user_id)
                && caller.uid == lease.uid
                && self.live_at(now)
        })
    }

    pub fn heartbeat(
        &mut self,
        caller: &Caller<'_>,
        generation: i64,
        sequence: i64,
        now: i64,
    ) -> bool {
        if !self.owns(caller, generation, now) || sequence <= self.heartbeat_sequence {
            return false;
        }
        self.heartbeat_time = now;
        self.heartbeat_sequence = sequence;
        true
    }

    pub fn begin_request(
        &mut self,
        caller: &Caller<'_>,
        generation: i64,
        request: Request,
        now: i64,
    ) -> Admission {
        if !self.owns(caller, generation, now) {
            return Admission::Revoked;
        }
        if request.request_id <= self.request_sequence
            || request.base_revision < 0
            || request.base_revision != request.actual_revision
            || request.topology_revision != self.topology_revision
        {
            return Admission::Stale;
        }
        if self.pending_request.is_some() {
            return Admission::Busy;
        }
        self.pending_request = Some(request.request_id);
        self.request_sequence = request.request_id;
        Admission::Accepted
    }

    pub fn finish_request(&mut self, generation: i64, request_id: i64, topology: i64) -> bool {
        if self
            .lease
            .is_none_or(|lease| lease.generation != generation)
            || self.pending_request != Some(request_id)
            || topology != self.topology_revision
        {
            return false;
        }
        self.pending_request = None;
        true
    }

    pub fn release(&mut self, caller: &Caller<'_>, generation: i64, now: i64) -> bool {
        if !self.owns(caller, generation, now) {
            return false;
        }
        self.clear();
        true
    }

    pub fn client_died(&mut self, generation: i64) -> bool {
        if self
            .lease
            .is_none_or(|lease| lease.generation != generation)
        {
            return false;
        }
        self.clear();
        true
    }

    fn clear(&mut self) {
        self.lease = None;
        self.displays = [EMPTY_DISPLAY; MAX_DISPLAYS];
        self.display_count = 0;
        self.topology_revision = -1;
        self.pending_request = None;
    }
}
