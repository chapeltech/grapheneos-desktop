package org.wonad.desktop.broker

import org.wonad.desktop.api.*

/** Private, bounded scalar packing only. Native objects, identity and
 * observations are resolved by the OS adapter; Rust independently validates
 * lengths, values and policy-neutral frame constraints after packing.
 */
internal object NativeDesktopWire {
    const val NATIVE_TASK_STATE_ROW = 13
    private fun bounds(value: DesktopRect) = listOf(value.left.toLong(), value.top.toLong(),
        value.right.toLong(), value.bottom.toLong())

    /** Private WMS rows are authenticated native observations, not APK frame
     * input. Validate the complete second observation before altering the
     * private Binder registry. The opaque identity and current UID are native
     * columns 11/12; numeric Android task IDs never enter this representation.
     */
    fun nativeTaskStateValid(rows: LongArray, expectedUids: IntArray, displayTokens: Set<Long>): Boolean {
        if (expectedUids.size > DesktopProtocol.MAX_TASKS || rows.size != expectedUids.size * NATIVE_TASK_STATE_ROW ||
            displayTokens.size > DesktopProtocol.MAX_DISPLAYS || displayTokens.any { it <= 0 }) return false
        val identities = hashSetOf<Long>()
        expectedUids.indices.forEach { index ->
            val at = index * NATIVE_TASK_STATE_ROW
            val edge = DesktopProtocol.MAX_COORDINATE.toLong()
            // Copy finite signed native observations without narrowing or
            // clamping. The RPC validator, not this observation codec, chooses
            // old contained versus new capability-gated desired geometry.
            if ((at until at + 4).any { rows[it] !in -edge..edge } ||
                rows[at + 2] - rows[at] !in 1L..edge || rows[at + 3] - rows[at + 1] !in 1L..edge ||
                rows[at + 4] !in 0L..Int.MAX_VALUE.toLong() || rows[at + 5] !in 0L..Int.MAX_VALUE.toLong() ||
                rows[at + 6] !in 0L..1L || rows[at + 7] !in 0L..1L || rows[at + 8] !in 0L..1L ||
                rows[at + 9] !in 0L..Int.MAX_VALUE.toLong() || rows[at + 10] !in displayTokens ||
                rows[at + 11] <= 0 || !identities.add(rows[at + 11]) || expectedUids[index] < 10000 ||
                rows[at + 12] != expectedUids[index].toLong()) return false
        }
        return true
    }

    /** Presence-only recheck used while a known native leaf reparents. Its
     * bounds/destination may still be settling, so it is deliberately not a
     * publishable snapshot and cannot be used to admit a frame or a lease.
     */
    fun nativeTaskIdentityMatches(row: LongArray, token: Long, uid: Int): Boolean =
        row.size == NATIVE_TASK_STATE_ROW && token > 0 && uid >= 10000 &&
            row[10] > 0 && row[11] == token && row[12] == uid.toLong()

    fun snapshot(snapshot: DesktopSnapshot): LongArray {
        require(snapshot.displays != null && snapshot.displays.size <= DesktopProtocol.MAX_DISPLAYS &&
            snapshot.tasks != null && snapshot.tasks.size <= DesktopProtocol.MAX_TASKS)
        return longArrayOf(snapshot.generation, snapshot.revision, snapshot.topologyRevision,
            snapshot.displays.size.toLong(), snapshot.tasks.size.toLong(),
            *snapshot.displays.flatMap { display -> listOf(display.token, display.displayId.toLong(),
                *bounds(display.bounds).toTypedArray(), display.densityDpi.toLong(),
                if (display.secure) 1L else 0L, display.shellGeneration) }.toLongArray(),
            *snapshot.tasks.flatMap { task -> listOf(task.token, task.displayToken, *bounds(task.bounds).toTypedArray(),
                task.minimumWidth.toLong(), task.minimumHeight.toLong(), if (task.resizable) 1L else 0L,
                if (task.visible) 1L else 0L, if (task.inputEnabled) 1L else 0L, task.zOrder.toLong()) }.toLongArray())
    }

    fun frame(generation: Long, base: Long, frame: DesktopFrame): LongArray {
        require(frame.placements != null && frame.placements.size <= DesktopProtocol.MAX_TASKS &&
            frame.shellRegions != null && frame.shellRegions.size <= DesktopProtocol.MAX_SHELL_REGIONS)
        return longArrayOf(generation, base, frame.topologyRevision, frame.focusedDisplayToken, frame.focusedToken,
            frame.placements.size.toLong(), frame.shellRegions.size.toLong(),
            *frame.placements.flatMap { placement -> listOf(placement.token, placement.destinationDisplayToken,
                *bounds(placement.bounds).toTypedArray(), if (placement.visible) 1L else 0L,
                if (placement.inputEnabled) 1L else 0L, placement.zOrder.toLong()) }.toLongArray(),
            *frame.shellRegions.flatMap { region -> listOf(region.generation, region.displayToken,
                *bounds(region.bounds).toTypedArray()) }.toLongArray())
    }
}
