//! A transition notification and matching observed WM state are both required.
//! This deadline is distinct from the functioning client's heartbeat deadline.
//! Shell's `aborted` flag also denotes empty/non-visible animations, not a
//! rejected WCT (pinned Transitions.dispatchReady). It cannot decide success
//! or failure: only the finished notification and actual state can do that.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum Completion {
    Waiting = 0,
    Applied = 1,
    PlatformConstraint = 2,
    TimedOut = 3,
}

pub fn observe(
    finished: bool,
    _animation_aborted: bool,
    now: i64,
    deadline: i64,
    matches: bool,
) -> Completion {
    if now < 0 || deadline < 0 {
        Completion::TimedOut
    } else if now >= deadline {
        if finished {
            Completion::PlatformConstraint
        } else {
            Completion::TimedOut
        }
    } else if finished && matches {
        Completion::Applied
    } else {
        Completion::Waiting
    }
}
