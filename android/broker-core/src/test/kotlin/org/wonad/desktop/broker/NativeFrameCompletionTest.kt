package org.wonad.desktop.broker

import org.junit.Assert.*
import org.junit.Test

/** Actual Kotlin/JNI/Rust boundary tests, not native WM runtime evidence. */
class NativeFrameCompletionTest {
    @Test fun firstPositiveAtOrAfterDeadlineNeverApplies() {
        assertEquals(NativeFrameCompletion.APPLIED, NativeFrameCompletion.observe(true, 14999, 15000))
        for (now in longArrayOf(15000, 15001, 30000, Long.MAX_VALUE)) {
            assertEquals(NativeFrameCompletion.PLATFORM_CONSTRAINT,
                NativeFrameCompletion.observe(true, now, 15000))
            assertEquals(NativeFrameCompletion.TIMED_OUT,
                NativeFrameCompletion.observe(false, now, 15000))
        }
        assertEquals(NativeFrameCompletion.WAITING, NativeFrameCompletion.observe(false, 14999, 15000))
        assertEquals(NativeFrameCompletion.TIMED_OUT, NativeFrameCompletion.observe(true, -1, 15000))
        assertEquals(NativeFrameCompletion.TIMED_OUT, NativeFrameCompletion.observe(true, 1, -1))
    }

    @Test fun aProofCallCrossingDeadlineMustUseItsReturnTime() {
        var now = 14900L
        val observed = run { now += 300; true }
        assertEquals(NativeFrameCompletion.PLATFORM_CONSTRAINT,
            NativeFrameCompletion.observe(observed, now, 15000))
    }

    @Test fun heartbeatAndRepeatedObservationCannotExtendDeadline() {
        val admittedDeadline = 15000L
        for (now in 0L until admittedDeadline step 1000L) {
            assertEquals(NativeFrameCompletion.WAITING,
                NativeFrameCompletion.observe(false, now, admittedDeadline))
        }
        assertEquals(NativeFrameCompletion.PLATFORM_CONSTRAINT,
            NativeFrameCompletion.observe(true, admittedDeadline, admittedDeadline))
        assertEquals(NativeFrameCompletion.PLATFORM_CONSTRAINT,
            NativeFrameCompletion.observe(true, admittedDeadline + 1, admittedDeadline))
    }
}
