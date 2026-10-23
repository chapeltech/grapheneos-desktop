use wonad_broker_core::layout::Rect;
use wonad_broker_core::native_frame::*;
use wonad_broker_core::ResultCode;

const AREA: Rect = Rect {
    left: 0,
    top: 0,
    right: 1920,
    bottom: 1080,
};
const DISPLAYS: [Display; 2] = [
    Display {
        token: 100,
        display_id: 2,
        bounds: AREA,
        density_dpi: 160,
        secure: true,
        shell_generation: 42,
    },
    Display {
        token: 200,
        display_id: 3,
        bounds: Rect {
            right: 1280,
            bottom: 720,
            ..AREA
        },
        density_dpi: 240,
        secure: true,
        shell_generation: 42,
    },
];
const FIRST_TASK: Task = Task {
    token: 7,
    display_token: 100,
    bounds: Rect {
        right: 640,
        bottom: 480,
        ..AREA
    },
    minimum_width: 100,
    minimum_height: 80,
    resizable: true,
    visible: true,
    input_enabled: true,
    z_order: 0,
};
const TASKS: [Task; 2] = [
    FIRST_TASK,
    Task {
        token: 8,
        display_token: 200,
        z_order: 1,
        ..FIRST_TASK
    },
];
const PLACEMENTS: [Placement; 2] = [
    Placement {
        token: 7,
        destination_display_token: 200,
        bounds: Rect {
            left: 3,
            top: 3,
            right: 1277,
            bottom: 717,
        },
        visible: true,
        input_enabled: true,
        z_order: 1,
    },
    Placement {
        token: 8,
        destination_display_token: 100,
        bounds: Rect {
            left: 3,
            top: 3,
            right: 1917,
            bottom: 1077,
        },
        visible: true,
        input_enabled: true,
        z_order: 0,
    },
];
const REGIONS: [ShellRegion; 2] = [
    ShellRegion {
        generation: 42,
        display_token: 100,
        bounds: Rect {
            right: 1920,
            bottom: 3,
            ..AREA
        },
    },
    ShellRegion {
        generation: 42,
        display_token: 200,
        bounds: Rect {
            right: 3,
            bottom: 720,
            ..AREA
        },
    },
];
fn current<'a>(displays: &'a [Display], tasks: &'a [Task]) -> Snapshot<'a> {
    Snapshot {
        generation: 42,
        revision: 9,
        topology: Topology {
            revision: 2,
            displays,
        },
        tasks,
    }
}
fn frame<'a>(placements: &'a [Placement], regions: &'a [ShellRegion]) -> Frame<'a> {
    Frame {
        generation: 42,
        base_revision: 9,
        topology_revision: 2,
        focused_display_token: 200,
        focused_token: 7,
        placements,
        shell_regions: regions,
    }
}

#[test]
fn complete_frame_has_no_workspace_or_reserved_panel_constraint() {
    assert_eq!(
        validate(&current(&DISPLAYS, &TASKS), &frame(&PLACEMENTS, &REGIONS)),
        ResultCode::Applied
    );
    let mut fullscreen = PLACEMENTS;
    fullscreen[0].bounds = DISPLAYS[1].bounds;
    fullscreen[1].bounds = DISPLAYS[0].bounds;
    assert_eq!(
        validate(&current(&DISPLAYS, &TASKS), &frame(&fullscreen, &[])),
        ResultCode::Applied
    );
    assert_eq!(
        validate(
            &current(&DISPLAYS, &TASKS),
            &frame(&[PLACEMENTS[1], PLACEMENTS[0]], &REGIONS)
        ),
        ResultCode::Applied
    );
    for token in [7, 8] {
        assert!(task_allowed(&current(&DISPLAYS, &TASKS), token, true));
    }
    for token in [-1, 0, 9] {
        assert!(!task_allowed(&current(&DISPLAYS, &TASKS), token, false));
    }
}

#[test]
fn only_complete_exact_native_task_display_and_z_identities_apply() {
    let snapshot = current(&DISPLAYS, &TASKS);
    assert_eq!(
        validate(&snapshot, &frame(&PLACEMENTS[..1], &[])),
        ResultCode::Invalid
    );
    assert_eq!(
        validate(&snapshot, &frame(&[PLACEMENTS[0]; 2], &[])),
        ResultCode::Invalid
    );
    for replacement in [
        Placement {
            token: 0,
            ..PLACEMENTS[0]
        },
        Placement {
            token: 9999,
            ..PLACEMENTS[0]
        },
        Placement {
            destination_display_token: 0,
            ..PLACEMENTS[0]
        },
        Placement {
            destination_display_token: 3,
            ..PLACEMENTS[0]
        }, // Android ID is not a token.
        Placement {
            destination_display_token: 201,
            ..PLACEMENTS[0]
        },
        Placement {
            z_order: -1,
            ..PLACEMENTS[0]
        },
        Placement {
            z_order: 0,
            ..PLACEMENTS[0]
        }, // duplicate z of second task
        Placement {
            z_order: 2,
            ..PLACEMENTS[0]
        },
        Placement {
            input_enabled: false,
            ..PLACEMENTS[0]
        },
        Placement {
            visible: false,
            ..PLACEMENTS[0]
        },
        Placement {
            bounds: Rect {
                left: -1,
                ..PLACEMENTS[0].bounds
            },
            ..PLACEMENTS[0]
        },
        Placement {
            bounds: Rect {
                right: 1281,
                ..PLACEMENTS[0].bounds
            },
            ..PLACEMENTS[0]
        },
        Placement {
            bounds: Rect {
                right: i32::MAX,
                bottom: i32::MAX,
                ..PLACEMENTS[0].bounds
            },
            ..PLACEMENTS[0]
        },
    ] {
        assert_eq!(
            validate(&snapshot, &frame(&[replacement, PLACEMENTS[1]], &[])),
            ResultCode::Invalid,
            "{replacement:?}"
        );
    }
    let mut recycled = DISPLAYS;
    recycled[1].token = 201;
    let mut moved = TASKS;
    moved[1].display_token = 201;
    assert_eq!(
        validate(&current(&recycled, &moved), &frame(&PLACEMENTS, &[])),
        ResultCode::Invalid
    );
}

#[test]
fn stale_generation_revision_and_topology_never_apply() {
    for (generation, base_revision, topology_revision) in
        [(41, 9, 2), (42, 8, 2), (42, 9, 1), (0, 9, 2)]
    {
        let mut desired = frame(&PLACEMENTS, &[]);
        desired.generation = generation;
        desired.base_revision = base_revision;
        desired.topology_revision = topology_revision;
        assert_eq!(
            validate(&current(&DISPLAYS, &TASKS), &desired),
            ResultCode::Stale
        );
    }
}

#[test]
fn hidden_tasks_lose_input_and_cannot_be_focused() {
    let mut hidden = PLACEMENTS;
    hidden[0].visible = false;
    hidden[0].input_enabled = false;
    assert_eq!(
        validate(&current(&DISPLAYS, &TASKS), &frame(&hidden, &[])),
        ResultCode::Invalid
    );
    let mut desired = frame(&hidden, &[]);
    desired.focused_token = 0;
    assert_eq!(
        validate(&current(&DISPLAYS, &TASKS), &desired),
        ResultCode::Applied
    );
    desired.focused_display_token = 0;
    desired.focused_token = 8;
    assert_eq!(
        validate(&current(&DISPLAYS, &TASKS), &desired),
        ResultCode::Invalid
    );
    let mut observed = TASKS;
    observed[0].visible = false;
    observed[0].input_enabled = false;
    assert!(!task_allowed(&current(&DISPLAYS, &observed), 7, true));
    assert!(task_allowed(&current(&DISPLAYS, &observed), 7, false));
}

#[test]
fn native_minimums_and_nonresizability_are_constraints_not_fake_success() {
    for task in [
        Task {
            minimum_width: 1400,
            ..TASKS[0]
        },
        Task {
            resizable: false,
            ..TASKS[0]
        },
    ] {
        assert_eq!(
            validate(
                &current(&DISPLAYS, &[task, TASKS[1]]),
                &frame(&PLACEMENTS, &[])
            ),
            ResultCode::PlatformConstraint
        );
    }
    for width in [1, 50, 99, 100, 1277] {
        for height in [1, 40, 79, 80, 717] {
            let mut placements = PLACEMENTS;
            placements[0].bounds = Rect {
                left: 0,
                top: 0,
                right: width,
                bottom: height,
            };
            assert_eq!(
                validate(&current(&DISPLAYS, &TASKS), &frame(&placements, &[])),
                if width < 100 || height < 80 {
                    ResultCode::PlatformConstraint
                } else {
                    ResultCode::Applied
                }
            );
        }
    }
}

#[test]
fn shell_regions_require_drawn_fixed_window_exact_generation_and_incarnation() {
    let mut displays = DISPLAYS;
    for generation in [0, 41, 43] {
        displays[0].shell_generation = generation;
        assert_eq!(
            validate(&current(&displays, &TASKS), &frame(&PLACEMENTS, &REGIONS)),
            ResultCode::Invalid
        );
        assert_eq!(
            validate(&current(&displays, &TASKS), &frame(&PLACEMENTS, &[])),
            ResultCode::Applied
        );
    }
    displays = DISPLAYS;
    displays[0].secure = false;
    assert_eq!(
        validate(&current(&displays, &TASKS), &frame(&PLACEMENTS, &REGIONS)),
        ResultCode::Invalid
    );
    for bad in [
        ShellRegion {
            generation: 41,
            ..REGIONS[0]
        },
        ShellRegion {
            display_token: 0,
            ..REGIONS[0]
        },
        ShellRegion {
            display_token: 2,
            ..REGIONS[0]
        },
        ShellRegion {
            bounds: Rect {
                right: 1921,
                ..REGIONS[0].bounds
            },
            ..REGIONS[0]
        },
        ShellRegion {
            bounds: Rect {
                bottom: 0,
                ..REGIONS[0].bounds
            },
            ..REGIONS[0]
        },
    ] {
        assert_eq!(
            validate(&current(&DISPLAYS, &TASKS), &frame(&PLACEMENTS, &[bad])),
            ResultCode::Invalid
        );
    }
    let whole = ShellRegion {
        bounds: AREA,
        ..REGIONS[0]
    };
    assert_eq!(
        validate(
            &current(&DISPLAYS, &TASKS),
            &frame(&PLACEMENTS, &[whole; MAX_SHELL_REGIONS])
        ),
        ResultCode::Applied
    );
    assert_eq!(
        validate(
            &current(&DISPLAYS, &TASKS),
            &frame(&PLACEMENTS, &[whole; MAX_SHELL_REGIONS + 1])
        ),
        ResultCode::Invalid
    );
}

#[test]
fn capacity_is_native_not_workspace_policy_and_phone_is_not_a_monitor() {
    let displays: [Display; MAX_DISPLAYS] = core::array::from_fn(|index| Display {
        display_id: index as i32 + 1,
        token: index as i64 + 10,
        ..DISPLAYS[0]
    });
    let mut desired = frame(&[], &[]);
    desired.focused_token = 0;
    desired.focused_display_token = 0;
    assert_eq!(
        validate(&current(&displays, &[]), &desired),
        ResultCode::Applied
    );
    for replacement in [
        Display {
            display_id: 0,
            ..DISPLAYS[0]
        },
        Display {
            token: 0,
            ..DISPLAYS[0]
        },
        Display {
            token: DISPLAYS[1].token,
            ..DISPLAYS[0]
        },
        Display {
            density_dpi: 0,
            ..DISPLAYS[0]
        },
    ] {
        assert!(!validate_topology(&Topology {
            revision: 1,
            displays: &[replacement, DISPLAYS[1]]
        }));
    }
    assert!(!validate_topology(&Topology {
        revision: 1,
        displays: &[DISPLAYS[0]; MAX_DISPLAYS + 1]
    }));
}

#[test]
fn completion_requires_actual_bounds_visibility_input_z_and_native_identity() {
    let actual = PLACEMENTS.map(|p| Task {
        token: p.token,
        display_token: p.destination_display_token,
        bounds: p.bounds,
        visible: p.visible,
        input_enabled: p.input_enabled,
        z_order: p.z_order,
        minimum_width: 100,
        minimum_height: 80,
        resizable: true,
    });
    assert!(placements_match(
        &current(&DISPLAYS, &actual),
        &frame(&PLACEMENTS, &REGIONS)
    ));
    assert!(!placements_match(
        &current(&DISPLAYS, &TASKS),
        &frame(&PLACEMENTS, &REGIONS)
    ));
    assert!(!placements_match(
        &current(&DISPLAYS, &actual),
        &frame(&[PLACEMENTS[0]; 2], &[])
    ));
    for task in [
        Task {
            bounds: Rect {
                left: 4,
                ..actual[0].bounds
            },
            ..actual[0]
        },
        Task {
            display_token: 100,
            ..actual[0]
        },
        Task {
            visible: false,
            input_enabled: false,
            ..actual[0]
        },
        Task {
            z_order: 0,
            ..actual[0]
        },
    ] {
        assert!(!placements_match(
            &current(&DISPLAYS, &[task, actual[1]]),
            &frame(&PLACEMENTS, &[])
        ));
    }
}
