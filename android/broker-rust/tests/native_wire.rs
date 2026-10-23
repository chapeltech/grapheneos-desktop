use wonad_broker_core::native_frame;
use wonad_broker_core::native_wire::*;
use wonad_broker_core::ResultCode;

fn observed() -> Vec<i64> {
    vec![
        42, 9, 2, 1, 1, 100, 2, 0, 0, 1920, 1080, 160, 1, 42, 7, 100, 3, 3, 1917, 1077, 100, 80, 1,
        1, 1, 0,
    ]
}
fn desired() -> Vec<i64> {
    vec![
        42, 9, 2, 100, 7, 1, 1, 7, 100, 3, 3, 1917, 1077, 1, 1, 0, 42, 100, 0, 0, 1920, 3,
    ]
}

#[test]
fn private_scalar_codec_is_exact_and_validates_a_real_neutral_frame() {
    assert_eq!(MAX_CURRENT_LONGS, 1622);
    assert_eq!(MAX_DESIRED_LONGS, 5767);
    let current = decode_snapshot(&observed()).unwrap();
    let frame = decode_frame(&desired()).unwrap();
    assert_eq!(
        native_frame::validate(&current.snapshot(), &frame.frame()),
        ResultCode::Applied
    );
    assert!(native_frame::placements_match(
        &current.snapshot(),
        &frame.frame()
    ));
}

#[test]
fn malformed_lengths_counts_flags_and_lossy_integers_are_rejected() {
    let observations = observed();
    for length in 0..observations.len() {
        assert!(decode_snapshot(&observations[..length]).is_none());
    }
    let frames = desired();
    for length in 0..frames.len() {
        assert!(decode_frame(&frames[..length]).is_none());
    }
    for (index, value) in [
        (3, -1),
        (3, 10),
        (4, -1),
        (4, 129),
        (4, i64::MAX),
        (6, i64::MAX),
        (10, i64::MAX),
        (12, 2),
        (22, -1),
        (24, 2),
    ] {
        let mut bad = observations.clone();
        bad[index] = value;
        assert!(
            decode_snapshot(&bad).is_none(),
            "observation index{index} value{value}"
        );
    }
    for (index, value) in [
        (5, -1),
        (5, 129),
        (6, -1),
        (6, 769),
        (6, i64::MAX),
        (11, i64::MAX),
        (13, 2),
        (14, -1),
        (15, i64::MAX),
    ] {
        let mut bad = frames.clone();
        bad[index] = value;
        assert!(
            decode_frame(&bad).is_none(),
            "frame index{index} value{value}"
        );
    }
    let mut extra = observations;
    extra.push(0);
    assert!(decode_snapshot(&extra).is_none());
    let mut extra = frames;
    extra.push(0);
    assert!(decode_frame(&extra).is_none());
}

#[test]
fn every_small_zero_fill_length_is_safe_not_a_hidden_frame_authority() {
    for length in 0..300 {
        if let Some(decoded) = decode_snapshot(&vec![0; length]) {
            assert!(!native_frame::validate_snapshot(&decoded.snapshot()));
        }
        if let Some(decoded) = decode_frame(&vec![0; length]) {
            assert_eq!(
                native_frame::validate(
                    &decode_snapshot(&observed()).unwrap().snapshot(),
                    &decoded.frame()
                ),
                ResultCode::Stale
            );
        }
    }
}
