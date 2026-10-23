"""Reparse the exact native claim's black/protected input-layer aliases.

One claim owns one channel and up to two surfaces. SurfaceFlinger retains a
hidden layer's input information with NOT_VISIBLE; InputDispatcher excludes
that layer from touch and occlusion. An alias is not permission to accept a
second active, foreign, differently scoped or malformed consumer.
"""
import re

ACTIVE = frozenset({"NOT_FOCUSABLE", "TRUSTED_OVERLAY"})
HIDDEN = ACTIVE | {"NOT_VISIBLE"}


def field(row, name, pattern):
    values = re.findall(r"(?<![\w.])" + re.escape(name) + "=(" + pattern + r")(?=,|$)", row)
    if len(values) != 1:
        raise ValueError("Missing/ambiguous consumer field: " + name)
    return values[0]


def _current_touch_rows(body):
    """Validate the pinned current touch/cursor grammar, retaining row indices.

    TouchedWindow::dump numbers its targets just like the window inventory.
    Those rows are *not* WindowInfo rows and must never populate that inventory
    or Connections. Neither ANR snapshots nor later IMS monitor lists enter
    this function: its caller supplies only the unique current Dispatcher body.
    """
    roots = []
    for title, empty in (("TouchStatesByDisplay", "<no displays touched>"),
                         ("CursorStatesByDisplay", "<no displays touched by cursor>")):
        matches = [i for i, line in enumerate(body) if line.startswith("  " + title + ":")]
        if len(matches) != 1:
            raise ValueError("Missing/ambiguous current Dispatcher " + title)
        index = matches[0]
        if body[index] not in ("  " + title + ":", "  " + title + ": " + empty):
            raise ValueError("Malformed current Dispatcher " + title)
        roots.append(index)
    first_display = next((i for i, line in enumerate(body) if line.startswith("  Display:")), len(body))
    if not roots[0] < roots[1] < first_display:
        raise ValueError("Reordered current Dispatcher touch/window sections")
    recognized = set()
    flags = {"FOREGROUND", "WINDOW_IS_OBSCURED", "SPLIT", "ZERO_COORDS", "NO_FOCUS_CHANGE",
             "WINDOW_IS_PARTIALLY_OBSCURED"}
    pointer = r"Pointer\(id=(?:[0-9]|[12][0-9]|3[01]), (?:UNKNOWN|FINGER|STYLUS|MOUSE|ERASER|PALM)\)"
    number = r"-?(?:\d+(?:\.\d*)?|\.\d+)(?:e[+-]?\d+)?"
    touching = r"(?:" + pointer + r"(?:, " + pointer + r")*)?"
    hover = pointer + r" at \(" + number + r", " + number + r"\)"
    hovering = r"(?:" + hover + r"(?:, " + hover + r")*)?"
    state_pattern = re.compile(r"          DeviceId\((-?\d+)\):\[touchingPointers=\[(" + touching +
        r")\], downTimeInTarget=(?:<none>|\d+), hoveringPointers=\[(" + hovering +
        r")\], pilferingPointerIds=(?:<none>|[01]{32})\]")
    for root in roots:
        stop = next((i for i in range(root + 1, len(body)) if re.match(r"^  \S", body[i])), len(body))
        content = [i for i in range(root + 1, stop) if body[i].strip()]
        if not body[root].endswith(":"):
            if content:
                raise ValueError("Rows beneath empty current Dispatcher touch section")
            continue
        if not content:
            raise ValueError("Empty populated current Dispatcher touch section")
        displays, display, section, index, devices = set(), None, False, 0, None
        for i in content:
            line = body[i]
            attached = re.fullmatch(r"    LogicalDisplayId (0|[1-9]\d*):", line)
            if attached:
                if display is not None and (not section or devices == set()):
                    raise ValueError("Incomplete current Dispatcher touched display/window")
                display = int(attached[1])
                if display in displays:
                    raise ValueError("Duplicate current Dispatcher touched display")
                displays.add(display); section, index, devices = False, 0, None
                continue
            if line in ("      TouchedWindows:", "      TouchedWindows: <none>"):
                if display is None or section:
                    raise ValueError("Reordered/duplicate current Dispatcher TouchedWindows")
                section = True
                if line.endswith("<none>"):
                    devices = None
                else:
                    devices = set()
                continue
            row = re.fullmatch(r"        (0|[1-9]\d*): name='[^'\n]+', targetFlags=([^,]+), "
                               r"forwardingWindowToken=(?:\(nil\)|0x[0-9a-f]+), mDeviceStates=", line)
            if row:
                if not section or devices is None or (index and not devices) or int(row[1]) != index:
                    raise ValueError("Reordered/incomplete current Dispatcher touching target")
                values = row[2].split(" | ")
                if row[2] != "0x0" and (len(values) != len(set(values)) or not set(values) <= flags):
                    raise ValueError("Malformed current Dispatcher target flags")
                recognized.add(i); index += 1; devices = set()
                continue
            state = state_pattern.fullmatch(line)
            if state:
                ident = int(state[1])
                if not section or not index or devices is None or ident in devices or \
                        not -2147483648 <= ident <= 2147483647 or not (state[2] or state[3]):
                    raise ValueError("Missing/duplicate/malformed current touching device state")
                for pointers in (state[2], state[3]):
                    ids = re.findall(r"Pointer\(id=(\d+),", pointers)
                    if len(ids) != len(set(ids)):
                        raise ValueError("Duplicate current touching pointer ID")
                devices.add(ident)
                continue
            raise ValueError("Malformed/extra current Dispatcher touch row")
        if not section or devices == set():
            raise ValueError("Incomplete current Dispatcher touching target")
    return recognized


def dispatcher_windows(raw):
    """Only current Dispatcher windows/connections, never ANR or IMS history.

    The pinned native dump emits one Display/Windows block per attachment.
    Validate rows before selecting the claim: malformed windows must not vanish
    merely because their inputConfig (or another required field) is missing.
    """
    lines = raw.splitlines()
    starts = [i for i, line in enumerate(lines) if line == "Input Dispatcher State:"]
    if len(starts) != 1:
        raise ValueError("Missing/ambiguous live InputDispatcher section")
    start = starts[0] + 1
    end = next((i for i in range(start, len(lines)) if lines[i] and not lines[i][0].isspace()), len(lines))
    body = lines[start:end]
    touch_rows = _current_touch_rows(body)
    rows, displays, layers = [], set(), set()
    display, windows, next_index = None, False, 0
    completed, connections = set(), []
    in_connections = False
    for row_index, line in enumerate(body):
        match = re.fullmatch(r"  Display: (0|[1-9]\d*)", line)
        if match:
            if connections or in_connections or (display is not None and display not in completed):
                raise ValueError("Reordered/incomplete Dispatcher display section")
            display = int(match[1])
            if display in displays:
                raise ValueError("Duplicate Dispatcher display section")
            displays.add(display)
            windows = False
            continue
        if line.startswith("  Display:"):
            raise ValueError("Malformed Dispatcher display section")
        if line in ("    Windows:", "    Windows: <none>"):
            if display is None or display in completed or in_connections:
                raise ValueError("Reordered/duplicate Dispatcher Windows section")
            completed.add(display)
            windows = line == "    Windows:"
            next_index = 0
            continue
        if line.lstrip().startswith("Windows:"):
            raise ValueError("Malformed Dispatcher Windows section")
        if line.startswith("  Connections:"):
            if connections or in_connections or not displays or displays != completed or \
                    line != "  Connections:":
                raise ValueError("Missing/reordered/duplicate Dispatcher Connections section")
            windows = False
            in_connections = True
            connections.append(line)
            continue
        if windows and (re.match(r"\s*-?\d+(?::|\s)", line) or re.search(r"\bname=", line)) and \
                re.fullmatch(r"      (0|[1-9]\d*): name=.+", line) is None:
            raise ValueError("Malformed Dispatcher window row")
        if line and re.match(r"^  \S", line):
            windows = False
            in_connections = False
        if in_connections:
            connections.append(line)
        if not windows and row_index not in touch_rows and re.match(r"\s*\d+: name=", line):
            raise ValueError("Window row outside Dispatcher Windows section")
        if windows and line.startswith("      ") and line[6:] and not line[6].isspace() and \
                not line[6:].startswith("transform "):
            window = re.fullmatch(r"      (0|[1-9]\d*): (name=.+)", line)
            if window is None or int(window[1]) != next_index:
                raise ValueError("Malformed/reordered Dispatcher window row")
            row = window[2]
            next_index += 1
            layer = int(field(row, "id", r"[1-9]\d*"))
            if layer in layers or int(field(row, "displayId", r"\d+")) != display:
                raise ValueError("Duplicate/foreign Dispatcher window identity")
            layers.add(layer)
            field(row, "name", r"[^,]+")
            field(row, "inputConfig", r"[^,]+")
            field(row, "ownerUid", r"\d+")
            field(row, "ownerPid", r"\d+")
            rows.append(row)
    if not displays or displays != completed or not connections:
        raise ValueError("Incomplete current Dispatcher window/connection sections")
    return rows, "\n".join(connections)


def consumers(raw, display, width, height, system_pid, mode="parked"):
    if any(type(value) is not int or value <= 0 for value in (display, width, height, system_pid)) or \
            mode not in ("parked", "protected", "live"):
        raise ValueError("Invalid observed consumer scope")
    rows, connection_section = dispatcher_windows(raw)
    name = "Wonad inactive " + str(display)
    selected = [row for row in rows if re.search(r"\bname=" + re.escape(name) + r",", row)]
    if not 1 <= len(selected) <= 2:
        raise ValueError("Missing or excessive claim consumer layers")
    full = "[0,0][" + str(width) + "," + str(height) + "]"
    identities, active, hidden, layers = set(), [], [], set()
    for row in selected:
        parts = field(row, "inputConfig", r"[^,]+").split("|")
        flags = frozenset(part.strip() for part in parts)
        if len(flags) != len(parts) or flags not in (ACTIVE, HIDDEN):
            raise ValueError("Unexpected consumer input flags")
        actual_name = field(row, "name", r"[^,]+")
        actual_display = int(field(row, "displayId", r"[1-9]\d*"))
        uid = int(field(row, "ownerUid", r"[1-9]\d*"))
        pid = int(field(row, "ownerPid", r"[1-9]\d*"))
        token = int(field(row, "token", r"0x[0-9a-f]{1,16}"), 16)
        layer = int(field(row, "id", r"[1-9]\d*"))
        rectangle = r"\[-?\d+,-?\d+\]\[-?\d+,-?\d+\]"
        if actual_name != name or actual_display != display or uid != 1000 or pid != system_pid or token <= 0 or \
                field(row, "frame", rectangle) != full or field(row, "touchableRegion", rectangle) != full or \
                field(row, "alpha", r"[\d.]+") != "1" or field(row, "globalScale", r"[\d.]+") != "1" or \
                field(row, "applicationInfo.token", r"[^,]+") != "<null>" or layer in layers:
            raise ValueError("Consumer identity/native scope differs")
        layers.add(layer); identities.add((actual_name, actual_display, uid, pid, token))
        (hidden if "NOT_VISIBLE" in flags else active).append(row)
    if len(identities) != 1 or len(active) != (0 if mode == "live" else 1) or \
            len(hidden) > (2 if mode == "live" else 1):
        raise ValueError("Consumer aliases are not one exact claim/one active layer")
    shared_token = next(iter(identities))[-1]
    for row in rows:
        if row in selected:
            continue
        tokens = re.findall(r"(?<![\w.])token=(0x[0-9a-f]+)(?=,|$)", row)
        if any(int(token, 16) == shared_token for token in tokens):
            raise ValueError("Claim channel token reused by an unrelated window")
        if active and field(row, "displayId", r"\d+") == str(display):
            flags = set(part.strip() for part in field(row, "inputConfig", r"[^,]+").split("|"))
            if "NOT_VISIBLE" not in flags and "SPY" not in flags and rows.index(row) < rows.index(active[0]):
                raise ValueError("Active consumer is below another visible window")
    connections = re.findall(r"^\s*\d+: channelName='" + re.escape(name) +
        r"', status=NORMAL, isFocusMonitor=false, responsive=true\s*$", connection_section, re.M)
    all_connections = re.findall(r"^\s*\d+: channelName='" + re.escape(name) + r"',.*$", connection_section, re.M)
    if len(connections) != 1 or len(all_connections) != 1:
        raise ValueError("Missing/duplicate/unresponsive claim channel connection")
    return dict(active=len(active), hidden=len(hidden), token=shared_token, layers=sorted(layers), mode=mode)
