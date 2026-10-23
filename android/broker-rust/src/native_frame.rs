//! Neutral protocol-v3 native observations and distinct bounded/signed frames.
//!
//! No workspace, desk, floating layout or reserved area exists here. The APK
//! chooses all such policy. Tokens are opaque OS-issued identities bound to
//! exact native objects, not recyclable Android IDs or Surface/Input handles.
//! Success is validation, never session authority or native transaction proof.
use crate::{layout::Rect, ResultCode, MAX_TASKS};

pub const API_VERSION: i32 = 3;
pub const MAX_DISPLAYS: usize = 9;
pub const MAX_SHELL_REGIONS: usize = 768;
pub const MAX_COORDINATE: i32 = 32_768;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Display {
    pub token: i64,
    pub display_id: i32,
    pub bounds: Rect,
    pub density_dpi: i32,
    pub secure: bool,
    /// OS registry observation: zero until the fixed own window draws.
    pub shell_generation: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct Topology<'a> {
    pub revision: i64,
    pub displays: &'a [Display],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Task {
    pub token: i64,
    pub display_token: i64,
    pub bounds: Rect,
    pub minimum_width: i32,
    pub minimum_height: i32,
    pub resizable: bool,
    pub visible: bool,
    pub input_enabled: bool,
    pub z_order: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Placement {
    pub token: i64,
    pub destination_display_token: i64,
    pub bounds: Rect,
    pub visible: bool,
    pub input_enabled: bool,
    pub z_order: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ShellRegion {
    pub generation: i64,
    pub display_token: i64,
    pub bounds: Rect,
}

pub struct Snapshot<'a> {
    pub generation: i64,
    pub revision: i64,
    pub topology: Topology<'a>,
    pub tasks: &'a [Task],
}

pub struct Frame<'a> {
    pub generation: i64,
    pub base_revision: i64,
    pub topology_revision: i64,
    /// Zero/zero retains focus. Nonzero display/zero task focuses desktop.
    pub focused_display_token: i64,
    pub focused_token: i64,
    pub placements: &'a [Placement],
    pub shell_regions: &'a [ShellRegion],
}

pub fn validate_topology(topology: &Topology<'_>) -> bool {
    topology.revision >= 0
        && !topology.displays.is_empty()
        && topology.displays.len() <= MAX_DISPLAYS
        && topology.displays.iter().enumerate().all(|(i, display)| {
            display.token > 0
                && display.display_id > 0
                && display.bounds.valid()
                && signed_bounds_valid(display.bounds)
                && display.density_dpi > 0
                && display.shell_generation >= 0
                && !topology.displays[..i].iter().any(|other| {
                    other.token == display.token || other.display_id == display.display_id
                })
        })
}

fn size(rect: Rect) -> (i64, i64) {
    (
        i64::from(rect.right) - i64::from(rect.left),
        i64::from(rect.bottom) - i64::from(rect.top),
    )
}

/// Protocol-v3 signed geometry; ordinary Rect::valid remains nonnegative.
/// Finite signed task rectangles may be partially or completely off-screen;
/// surface/input ownership is still an exact leased external DisplayContent.
/// Shell regions and physical input viewports remain strictly monitor-clipped.
pub fn signed_bounds_valid(rect: Rect) -> bool {
    let dimensions = size(rect);
    [rect.left, rect.top, rect.right, rect.bottom]
        .iter()
        .all(|edge| (-MAX_COORDINATE..=MAX_COORDINATE).contains(edge))
        && (1..=i64::from(MAX_COORDINATE)).contains(&dimensions.0)
        && (1..=i64::from(MAX_COORDINATE)).contains(&dimensions.1)
}

pub fn validate_snapshot(snapshot: &Snapshot<'_>) -> bool {
    snapshot.generation > 0
        && snapshot.revision >= 0
        && validate_topology(&snapshot.topology)
        && snapshot.tasks.len() <= MAX_TASKS
        && snapshot.tasks.iter().enumerate().all(|(i, task)| {
            task.token > 0
                && signed_bounds_valid(task.bounds)
                && task.minimum_width >= 0
                && task.minimum_height >= 0
                && task.input_enabled == task.visible
                && task.z_order >= 0
                && (task.z_order as usize) < snapshot.tasks.len()
                && snapshot
                    .topology
                    .displays
                    .iter()
                    .any(|display| display.token == task.display_token)
                && !snapshot.tasks[..i]
                    .iter()
                    .any(|other| other.token == task.token || other.z_order == task.z_order)
        })
}

/// Check fresh trusted OS observations on the serialized native executor.
/// All tracked tasks occur exactly once, including hidden ones. No phone task
/// may be imported by supplying a token: only already imported observations
/// are accepted. Exact native identities must be rechecked before execution.
pub fn validate(current: &Snapshot<'_>, desired: &Frame<'_>) -> ResultCode {
    validate_geometry(current, desired, false)
}

/// Additive negotiated signed-placement RPC. This does not widen applyFrame:
/// its DESIRED task rectangles remain strictly contained. Signed current
/// observations let either RPC recover an existing off-screen task. Geometry
/// validity does not authenticate or grant a capability/lease; the native OS
/// must independently resolve exact task/display/user identities and clip all
/// rendering/input to their destination's actual viewport before application.
pub fn validate_signed(current: &Snapshot<'_>, desired: &Frame<'_>) -> ResultCode {
    validate_geometry(current, desired, true)
}

fn validate_geometry(current: &Snapshot<'_>, desired: &Frame<'_>, signed: bool) -> ResultCode {
    if !validate_snapshot(current) {
        return ResultCode::Invalid;
    }
    if desired.generation != current.generation
        || desired.base_revision != current.revision
        || desired.topology_revision != current.topology.revision
    {
        return ResultCode::Stale;
    }
    if desired.placements.len() != current.tasks.len()
        || desired.shell_regions.len() > MAX_SHELL_REGIONS
        || desired.focused_display_token < 0
        || desired.focused_token < 0
        || (desired.focused_display_token == 0 && desired.focused_token != 0)
        || (desired.focused_display_token > 0
            && !current
                .topology
                .displays
                .iter()
                .any(|display| display.token == desired.focused_display_token))
    {
        return ResultCode::Invalid;
    }
    let mut focused_visible = desired.focused_token == 0;
    let mut result = ResultCode::Applied;
    for (index, placement) in desired.placements.iter().enumerate() {
        let Some(task) = current
            .tasks
            .iter()
            .find(|task| task.token == placement.token)
        else {
            return ResultCode::Invalid;
        };
        let Some(display) = current
            .topology
            .displays
            .iter()
            .find(|display| display.token == placement.destination_display_token)
        else {
            return ResultCode::Invalid;
        };
        if placement.z_order < 0
            || placement.z_order as usize >= desired.placements.len()
            || desired.placements[..index]
                .iter()
                .any(|other| other.token == placement.token || other.z_order == placement.z_order)
            || !signed_bounds_valid(placement.bounds)
            || (!signed && !display.bounds.contains(placement.bounds))
            || placement.input_enabled != placement.visible
        {
            return ResultCode::Invalid;
        }
        let dimensions = size(placement.bounds);
        if dimensions.0 < i64::from(task.minimum_width)
            || dimensions.1 < i64::from(task.minimum_height)
            || (!task.resizable && dimensions != size(task.bounds))
        {
            result = ResultCode::PlatformConstraint;
        }
        if placement.token == desired.focused_token
            && placement.visible
            && placement.destination_display_token == desired.focused_display_token
        {
            focused_visible = true;
        }
    }
    for region in desired.shell_regions {
        let Some(display) = current
            .topology
            .displays
            .iter()
            .find(|display| display.token == region.display_token)
        else {
            return ResultCode::Invalid;
        };
        if region.generation != current.generation
            || display.shell_generation != current.generation
            || !display.secure
            || !display.bounds.contains(region.bounds)
        {
            return ResultCode::Invalid;
        }
    }
    if focused_visible {
        result
    } else {
        ResultCode::Invalid
    }
}

/// Completion is an actual native observation, not a transition ACK. Snapshot
/// revision may advance, but topology/native identities and every requested
/// bound, input/visibility bit and z-order must still match. Shell-region
/// installation and native focus are separately observed by the OS adapter.
pub fn placements_match(current: &Snapshot<'_>, desired: &Frame<'_>) -> bool {
    validate_snapshot(current)
        && current.generation == desired.generation
        && current.revision >= desired.base_revision
        && current.topology.revision == desired.topology_revision
        && current.tasks.len() == desired.placements.len()
        && desired
            .placements
            .iter()
            .enumerate()
            .all(|(index, placement)| {
                !desired.placements[..index].iter().any(|other| {
                    other.token == placement.token || other.z_order == placement.z_order
                }) && current.tasks.iter().any(|task| {
                    task.token == placement.token
                        && task.display_token == placement.destination_display_token
                        && task.bounds == placement.bounds
                        && task.visible == placement.visible
                        && task.input_enabled == placement.input_enabled
                        && task.z_order == placement.z_order
                })
            })
}

pub fn task_allowed(current: &Snapshot<'_>, token: i64, needs_input: bool) -> bool {
    validate_snapshot(current)
        && token > 0
        && current.tasks.iter().any(|task| {
            task.token == token && (!needs_input || (task.visible && task.input_enabled))
        })
}

#[cfg(test)]
mod signed_tests {
    use super::*;
    const AREA: Rect = Rect {
        left: 0,
        top: 0,
        right: 1024,
        bottom: 768,
    };
    const DISPLAY: Display = Display {
        token: 100,
        display_id: 2,
        bounds: AREA,
        density_dpi: 160,
        secure: true,
        shell_generation: 42,
    };
    const TASK: Task = Task {
        token: 7,
        display_token: 100,
        bounds: AREA,
        minimum_width: 100,
        minimum_height: 80,
        resizable: true,
        visible: true,
        input_enabled: true,
        z_order: 0,
    };
    fn snapshot<'a>(displays: &'a [Display], tasks: &'a [Task]) -> Snapshot<'a> {
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
    fn placement(bounds: Rect) -> Placement {
        Placement {
            token: 7,
            destination_display_token: 100,
            bounds,
            visible: true,
            input_enabled: true,
            z_order: 0,
        }
    }
    fn frame<'a>(placements: &'a [Placement], shell_regions: &'a [ShellRegion]) -> Frame<'a> {
        Frame {
            generation: 42,
            base_revision: 9,
            topology_revision: 2,
            focused_display_token: 100,
            focused_token: 7,
            placements,
            shell_regions,
        }
    }

    #[test]
    fn partial_negative_and_fully_offscreen_are_new_rpc_only() {
        let current = snapshot(&[DISPLAY], &[TASK]);
        for bounds in [
            Rect {
                left: 53,
                top: 53,
                right: 1071,
                bottom: 431,
            }, // genuine initial Linux float content
            Rect {
                left: -100,
                top: -50,
                right: 918,
                bottom: 712,
            },
            Rect {
                left: 2000,
                top: 2000,
                right: 3018,
                bottom: 2762,
            },
            Rect {
                left: -2000,
                top: -2000,
                right: -982,
                bottom: -1238,
            },
        ] {
            let placements = [placement(bounds)];
            assert!(signed_bounds_valid(bounds));
            assert_eq!(
                validate_signed(&current, &frame(&placements, &[])),
                ResultCode::Applied
            );
            assert_eq!(
                validate(&current, &frame(&placements, &[])),
                ResultCode::Invalid
            );
        }
        assert_eq!(
            validate_signed(&current, &frame(&[placement(AREA)], &[])),
            ResultCode::Applied
        );
        assert_eq!(
            validate(&current, &frame(&[placement(AREA)], &[])),
            ResultCode::Applied
        );
    }

    #[test]
    fn signed_observations_can_be_recovered_by_old_bounded_frame() {
        let task = Task {
            bounds: Rect {
                left: -100,
                top: -50,
                right: 918,
                bottom: 712,
            },
            ..TASK
        };
        let tasks = [task];
        let current = snapshot(&[DISPLAY], &tasks);
        assert!(validate_snapshot(&current));
        assert!(task_allowed(&current, 7, true));
        let recovery = [placement(AREA)];
        assert_eq!(
            validate(&current, &frame(&recovery, &[])),
            ResultCode::Applied
        );
        assert!(!placements_match(&current, &frame(&recovery, &[])));
        let desired = [placement(task.bounds)];
        assert!(placements_match(&current, &frame(&desired, &[])));
        assert_eq!(
            validate(&current, &frame(&desired, &[])),
            ResultCode::Invalid
        );
    }

    #[test]
    fn finite_geometry_is_checked_without_signed_overflow_or_bounded_rpc_change() {
        let current = snapshot(&[DISPLAY], &[TASK]);
        for bounds in [
            Rect {
                left: -32769,
                top: 0,
                right: 0,
                bottom: 100,
            },
            Rect {
                left: 0,
                top: 0,
                right: 32769,
                bottom: 100,
            },
            Rect {
                left: -32768,
                top: 0,
                right: 32768,
                bottom: 100,
            },
            Rect {
                left: 0,
                top: 10,
                right: 100,
                bottom: 10,
            },
            Rect {
                left: 10,
                top: 0,
                right: 10,
                bottom: 100,
            },
            Rect {
                left: 10,
                top: 0,
                right: 9,
                bottom: 100,
            },
            Rect {
                left: i32::MIN,
                top: i32::MIN,
                right: i32::MAX,
                bottom: i32::MAX,
            },
        ] {
            assert!(!signed_bounds_valid(bounds));
            assert_eq!(
                validate_signed(&current, &frame(&[placement(bounds)], &[])),
                ResultCode::Invalid
            );
            assert!(!validate_snapshot(&snapshot(
                &[DISPLAY],
                &[Task { bounds, ..TASK }]
            )));
        }
        for bounds in [
            Rect {
                left: -32768,
                top: -32768,
                right: 0,
                bottom: 0,
            },
            Rect {
                left: 0,
                top: 0,
                right: 32768,
                bottom: 32768,
            },
            Rect {
                left: -1,
                top: -1,
                right: 0,
                bottom: 0,
            },
        ] {
            assert!(signed_bounds_valid(bounds));
        }
        assert!(!Rect {
            left: -1,
            top: -1,
            right: 100,
            bottom: 100
        }
        .valid());
        assert!(!AREA.contains(Rect {
            left: -1,
            top: 0,
            right: 100,
            bottom: 100
        }));
    }

    #[test]
    fn signed_rpc_keeps_native_minimum_and_fixed_size_constraints() {
        let desired = [placement(Rect {
            left: -50,
            top: -50,
            right: 0,
            bottom: 0,
        })];
        assert_eq!(
            validate_signed(&snapshot(&[DISPLAY], &[TASK]), &frame(&desired, &[])),
            ResultCode::PlatformConstraint
        );
        let fixed = [Task {
            resizable: false,
            ..TASK
        }];
        assert_eq!(
            validate_signed(&snapshot(&[DISPLAY], &fixed), &frame(&desired, &[])),
            ResultCode::PlatformConstraint
        );
        let moved = [placement(Rect {
            left: -100,
            top: -100,
            right: 924,
            bottom: 668,
        })];
        assert_eq!(
            validate_signed(&snapshot(&[DISPLAY], &fixed), &frame(&moved, &[])),
            ResultCode::Applied
        );
    }

    #[test]
    fn signed_rpc_does_not_extend_region_or_destination_or_hidden_focus_authority() {
        let current = snapshot(&[DISPLAY], &[TASK]);
        let placements = [placement(Rect {
            left: -100,
            top: -50,
            right: 918,
            bottom: 712,
        })];
        for region in [
            ShellRegion {
                generation: 42,
                display_token: 100,
                bounds: Rect { left: -1, ..AREA },
            },
            ShellRegion {
                generation: 42,
                display_token: 100,
                bounds: Rect {
                    right: 1025,
                    ..AREA
                },
            },
            ShellRegion {
                generation: 41,
                display_token: 100,
                bounds: AREA,
            },
            ShellRegion {
                generation: 42,
                display_token: 0,
                bounds: AREA,
            },
            ShellRegion {
                generation: 42,
                display_token: 2,
                bounds: AREA,
            },
        ] {
            assert_eq!(
                validate_signed(&current, &frame(&placements, &[region])),
                ResultCode::Invalid
            );
        }
        for destination in [0, 2, 101] {
            assert_eq!(
                validate_signed(
                    &current,
                    &frame(
                        &[Placement {
                            destination_display_token: destination,
                            ..placements[0]
                        }],
                        &[]
                    )
                ),
                ResultCode::Invalid
            );
        }
        for task in [0, 8] {
            assert_eq!(
                validate_signed(
                    &current,
                    &frame(
                        &[Placement {
                            token: task,
                            ..placements[0]
                        }],
                        &[]
                    )
                ),
                ResultCode::Invalid
            );
        }
        let hidden = [Placement {
            visible: false,
            input_enabled: false,
            ..placements[0]
        }];
        assert_eq!(
            validate_signed(&current, &frame(&hidden, &[])),
            ResultCode::Invalid
        );
        let mut no_focus = frame(&hidden, &[]);
        no_focus.focused_token = 0;
        assert_eq!(validate_signed(&current, &no_focus), ResultCode::Applied);
        assert_eq!(
            validate_signed(
                &current,
                &frame(
                    &[Placement {
                        input_enabled: false,
                        ..placements[0]
                    }],
                    &[]
                )
            ),
            ResultCode::Invalid
        );
        let mut stale = frame(&placements, &[]);
        stale.generation -= 1;
        assert_eq!(validate_signed(&current, &stale), ResultCode::Stale);
        stale = frame(&placements, &[]);
        stale.base_revision -= 1;
        assert_eq!(validate_signed(&current, &stale), ResultCode::Stale);
        stale = frame(&placements, &[]);
        stale.topology_revision -= 1;
        assert_eq!(validate_signed(&current, &stale), ResultCode::Stale);
        let phone = [Display {
            display_id: 0,
            ..DISPLAY
        }];
        assert_eq!(
            validate_signed(&snapshot(&phone, &[TASK]), &frame(&placements, &[])),
            ResultCode::Invalid
        );
    }
}
