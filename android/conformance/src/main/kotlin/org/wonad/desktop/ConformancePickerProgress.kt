package org.wonad.desktop

import org.wonad.desktop.api.DesktopSnapshot

/** Private conformance-harness sequencing, not an addition to the frozen SDK.
 * The pinned broker currently admits catalogue opens at least 1,000ms apart,
 * even after cancellation. Its public admission/cadence documentation gap is
 * still open; respecting this source-proven bound does not prove that it caused
 * the previous runtime failure. */
internal object ConformancePickerProgress {
    private const val CATALOGUE_INTERVAL_MILLIS = 1_000L
    private const val SLEEP_SLICE_MILLIS = 100L
    private const val MAX_SLEEPS = 10

    data class State(val generation: Long, val revision: Long, val interactionBlocked: Boolean)
    fun observe(value: DesktopSnapshot) = State(value.generation, value.revision, value.interactionBlocked)

    fun opened(value: State, generation: Long, beforeRevision: Long): Boolean =
        generation > 0 && beforeRevision > 0 && value.generation == generation &&
            value.revision > beforeRevision && value.interactionBlocked

    fun cancellationFloor(value: State, generation: Long, openedRevision: Long): Long {
        check(generation > 0 && openedRevision > 0 && value.generation == generation &&
            value.revision >= openedRevision && value.interactionBlocked) {
            "launcher cancellation has no current blocked observation"
        }
        return value.revision
    }

    fun cancelled(value: State, generation: Long, beforeRevision: Long): Boolean =
        generation > 0 && beforeRevision > 0 && value.generation == generation &&
            value.revision > beforeRevision && !value.interactionBlocked

    /** One bounded monotonic wait before one request, never a picker retry.
     * A first synchronous catalogue return is conservatively later than the
     * native open which produced it. Interrupted/frozen/regressing clocks and
     * invalid/overflowed anchors fail before the next request. */
    fun awaitCatalogueCadence(returnedElapsed: Long, clock: () -> Long, sleep: (Long) -> Unit) {
        check(returnedElapsed >= 0) { "negative catalogue-return clock" }
        val earliest = Math.addExact(returnedElapsed, CATALOGUE_INTERVAL_MILLIS)
        var previous = returnedElapsed
        repeat(MAX_SLEEPS + 1) { attempt ->
            if (Thread.currentThread().isInterrupted) throw InterruptedException("picker cadence interrupted")
            val now = clock()
            check(now >= previous) { "picker cadence clock regressed" }
            if (now >= earliest) return
            check(attempt < MAX_SLEEPS) { "picker cadence clock did not advance within its bounded wait" }
            previous = now
            sleep(minOf(SLEEP_SLICE_MILLIS, earliest - now))
        }
    }
}
