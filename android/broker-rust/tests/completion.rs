use wonad_broker_core::completion::{observe, Completion::*};

#[test]
fn bounds_alone_do_not_prove_a_finished_transition() {
    assert_eq!(Waiting, observe(false, false, 100, 200, true));
}

#[test]
fn task_information_may_arrive_after_transition_finish() {
    assert_eq!(Waiting, observe(true, false, 100, 200, false));
    assert_eq!(Applied, observe(true, false, 101, 200, true));
}

#[test]
fn animation_abort_is_not_a_failed_window_transaction_but_deadlines_are_final() {
    assert_eq!(Waiting, observe(false, true, 100, 200, true));
    assert_eq!(Waiting, observe(true, true, 100, 200, false));
    assert_eq!(Applied, observe(true, true, 100, 200, true));
    assert_eq!(PlatformConstraint, observe(true, true, 200, 200, true));
    assert_eq!(PlatformConstraint, observe(true, false, 200, 200, false));
    assert_eq!(TimedOut, observe(false, false, 200, 200, true));
    assert_eq!(TimedOut, observe(true, false, -1, 200, true));
    assert_eq!(TimedOut, observe(true, false, 100, -1, true));
}

#[test]
fn success_requires_every_positive_observation_before_the_deadline() {
    for finished in [false, true] {
        for aborted in [false, true] {
            for matches in [false, true] {
                for now in [-1, 0, 199, 200, i64::MAX] {
                    assert_eq!(
                        finished && matches && (0..200).contains(&now),
                        observe(finished, aborted, now, 200, matches) == Applied
                    );
                }
            }
        }
    }
}
