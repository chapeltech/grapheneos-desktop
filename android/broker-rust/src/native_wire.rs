//! Private JNI scalar codec for v3. No allocation, native pointer or Android
//! object is encoded. Fresh OS rows and APK request rows MUST remain separate.
//! Length/count arithmetic is checked before slicing; booleans accept 0/1 only.
use crate::layout::Rect;
use crate::native_frame::{
    Display, Frame, Placement, ShellRegion, Snapshot, Task, Topology, MAX_DISPLAYS,
    MAX_SHELL_REGIONS,
};
use crate::MAX_TASKS;

pub const CURRENT_HEADER: usize = 5;
pub const DISPLAY_ROW: usize = 9;
pub const TASK_ROW: usize = 12;
pub const DESIRED_HEADER: usize = 7;
pub const PLACEMENT_ROW: usize = 9;
pub const REGION_ROW: usize = 6;
pub const MAX_CURRENT_LONGS: usize =
    CURRENT_HEADER + MAX_DISPLAYS * DISPLAY_ROW + MAX_TASKS * TASK_ROW;
pub const MAX_DESIRED_LONGS: usize =
    DESIRED_HEADER + MAX_TASKS * PLACEMENT_ROW + MAX_SHELL_REGIONS * REGION_ROW;

const EMPTY_RECT: Rect = Rect {
    left: 0,
    top: 0,
    right: 0,
    bottom: 0,
};
const EMPTY_DISPLAY: Display = Display {
    token: 0,
    display_id: 0,
    bounds: EMPTY_RECT,
    density_dpi: 0,
    secure: false,
    shell_generation: 0,
};
const EMPTY_TASK: Task = Task {
    token: 0,
    display_token: 0,
    bounds: EMPTY_RECT,
    minimum_width: 0,
    minimum_height: 0,
    resizable: false,
    visible: false,
    input_enabled: false,
    z_order: 0,
};
const EMPTY_PLACEMENT: Placement = Placement {
    token: 0,
    destination_display_token: 0,
    bounds: EMPTY_RECT,
    visible: false,
    input_enabled: false,
    z_order: 0,
};
const EMPTY_REGION: ShellRegion = ShellRegion {
    generation: 0,
    display_token: 0,
    bounds: EMPTY_RECT,
};

pub struct Observed {
    generation: i64,
    revision: i64,
    topology_revision: i64,
    displays: [Display; MAX_DISPLAYS],
    display_count: usize,
    tasks: [Task; MAX_TASKS],
    task_count: usize,
}

impl Observed {
    pub fn snapshot(&self) -> Snapshot<'_> {
        Snapshot {
            generation: self.generation,
            revision: self.revision,
            topology: Topology {
                revision: self.topology_revision,
                displays: &self.displays[..self.display_count],
            },
            tasks: &self.tasks[..self.task_count],
        }
    }
}

pub struct Desired {
    generation: i64,
    base_revision: i64,
    topology_revision: i64,
    focused_display_token: i64,
    focused_token: i64,
    placements: [Placement; MAX_TASKS],
    placement_count: usize,
    regions: [ShellRegion; MAX_SHELL_REGIONS],
    region_count: usize,
}

impl Desired {
    pub fn frame(&self) -> Frame<'_> {
        Frame {
            generation: self.generation,
            base_revision: self.base_revision,
            topology_revision: self.topology_revision,
            focused_display_token: self.focused_display_token,
            focused_token: self.focused_token,
            placements: &self.placements[..self.placement_count],
            shell_regions: &self.regions[..self.region_count],
        }
    }
}

fn integer(value: i64) -> Option<i32> {
    i32::try_from(value).ok()
}
fn boolean(value: i64) -> Option<bool> {
    match value {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}
fn count(value: i64, maximum: usize) -> Option<usize> {
    usize::try_from(value)
        .ok()
        .filter(|&value| value <= maximum)
}
fn rect(values: &[i64]) -> Option<Rect> {
    let [left, top, right, bottom] = values else {
        return None;
    };
    Some(Rect {
        left: integer(*left)?,
        top: integer(*top)?,
        right: integer(*right)?,
        bottom: integer(*bottom)?,
    })
}

/// header: generation, revision, topologyRevision, displayCount, taskCount.
/// display: token, displayId, l,t,r,b, density, secure, shellGeneration.
/// task: token, displayToken, l,t,r,b, minW,minH, resizable,visible,input,zOrder.
/// Task coordinates are copied losslessly as signed i32; native_frame validates
/// their finite native-v3 range. Display rectangles remain nonnegative. This
/// scalar codec is not an authorization or signed-placement capability grant.
pub fn decode_snapshot(values: &[i64]) -> Option<Observed> {
    let header = values.get(..CURRENT_HEADER)?;
    let display_count = count(header[3], MAX_DISPLAYS)?;
    let task_count = count(header[4], MAX_TASKS)?;
    let task_start = CURRENT_HEADER.checked_add(display_count.checked_mul(DISPLAY_ROW)?)?;
    let end = task_start.checked_add(task_count.checked_mul(TASK_ROW)?)?;
    if values.len() != end {
        return None;
    }
    let mut observed = Observed {
        generation: header[0],
        revision: header[1],
        topology_revision: header[2],
        display_count,
        task_count,
        displays: [EMPTY_DISPLAY; MAX_DISPLAYS],
        tasks: [EMPTY_TASK; MAX_TASKS],
    };
    for (index, row) in values[CURRENT_HEADER..task_start]
        .chunks_exact(DISPLAY_ROW)
        .enumerate()
    {
        observed.displays[index] = Display {
            token: row[0],
            display_id: integer(row[1])?,
            bounds: rect(&row[2..6])?,
            density_dpi: integer(row[6])?,
            secure: boolean(row[7])?,
            shell_generation: row[8],
        };
    }
    for (index, row) in values[task_start..].chunks_exact(TASK_ROW).enumerate() {
        observed.tasks[index] = Task {
            token: row[0],
            display_token: row[1],
            bounds: rect(&row[2..6])?,
            minimum_width: integer(row[6])?,
            minimum_height: integer(row[7])?,
            resizable: boolean(row[8])?,
            visible: boolean(row[9])?,
            input_enabled: boolean(row[10])?,
            z_order: integer(row[11])?,
        };
    }
    Some(observed)
}

/// header: generation, baseRevision, topologyRevision, focusedDisplayToken,
/// focusedToken, placementCount, shellRegionCount.
/// placement: token, destinationDisplayToken, l,t,r,b, visible,input,zOrder.
/// region: generation, displayToken, l,t,r,b.
/// Same scalar shapes for old bounded/new signed RPCs. The native_frame entry
/// point, never an untrusted extra wire flag, selects desired-task semantics.
pub fn decode_frame(values: &[i64]) -> Option<Desired> {
    let header = values.get(..DESIRED_HEADER)?;
    let placement_count = count(header[5], MAX_TASKS)?;
    let region_count = count(header[6], MAX_SHELL_REGIONS)?;
    let region_start = DESIRED_HEADER.checked_add(placement_count.checked_mul(PLACEMENT_ROW)?)?;
    let end = region_start.checked_add(region_count.checked_mul(REGION_ROW)?)?;
    if values.len() != end {
        return None;
    }
    let mut desired = Desired {
        generation: header[0],
        base_revision: header[1],
        topology_revision: header[2],
        focused_display_token: header[3],
        focused_token: header[4],
        placement_count,
        region_count,
        placements: [EMPTY_PLACEMENT; MAX_TASKS],
        regions: [EMPTY_REGION; MAX_SHELL_REGIONS],
    };
    for (index, row) in values[DESIRED_HEADER..region_start]
        .chunks_exact(PLACEMENT_ROW)
        .enumerate()
    {
        desired.placements[index] = Placement {
            token: row[0],
            destination_display_token: row[1],
            bounds: rect(&row[2..6])?,
            visible: boolean(row[6])?,
            input_enabled: boolean(row[7])?,
            z_order: integer(row[8])?,
        };
    }
    for (index, row) in values[region_start..].chunks_exact(REGION_ROW).enumerate() {
        desired.regions[index] = ShellRegion {
            generation: row[0],
            display_token: row[1],
            bounds: rect(&row[2..6])?,
        };
    }
    Some(desired)
}
