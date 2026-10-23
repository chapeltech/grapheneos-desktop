package org.wonad.fixture

import org.junit.Assert.*
import org.junit.Test

class KeyboardCaptureCountersTest {
    @Test fun initialStateIsEmpty() {
        val actual = KeyboardCaptureCounters().snapshot()
        assertEquals(0, actual.downs); assertEquals(0, actual.ups)
        assertEquals(0, actual.escapeDowns); assertEquals(0, actual.escapeUps)
        assertFalse(actual.saturated)
    }
    @Test fun genericKeysHaveOnlyAggregateCounts() {
        val counter = KeyboardCaptureCounters()
        counter.observe(0, false, 0, false); counter.observe(1, false, 0, false)
        val actual = counter.snapshot()
        assertEquals(1, actual.downs); assertEquals(1, actual.ups)
        assertEquals(0, actual.escapeDowns); assertEquals(0, actual.escapeUps)
    }
    @Test fun escapeAndRepeatCountsRemainSeparate() {
        val counter = KeyboardCaptureCounters()
        counter.observe(0, true, 0, false); counter.observe(0, true, 1, false)
        counter.observe(1, true, 0, true)
        val actual = counter.snapshot()
        assertEquals(2, actual.downs); assertEquals(1, actual.ups)
        assertEquals(2, actual.escapeDowns); assertEquals(1, actual.escapeUps)
        assertEquals(1, actual.repeats); assertEquals(1, actual.canceled)
    }
    @Test fun countersSaturateWithoutOverflowOrHistory() {
        val counter = KeyboardCaptureCounters(2)
        repeat(4) { counter.observe(0, true, 1, true) }
        val actual = counter.snapshot()
        assertEquals(2, actual.downs); assertEquals(2, actual.escapeDowns)
        assertEquals(2, actual.repeats); assertEquals(2, actual.canceled)
        assertTrue(actual.saturated)
    }
    @Test fun clearResetsOnlyAggregateState() {
        val counter = KeyboardCaptureCounters(1)
        repeat(2) { counter.observe(0, true, 1, true) }; counter.clear()
        assertEquals(KeyboardCaptureCounters.Snapshot(0, 0, 0, 0, 0, 0, 0, false), counter.snapshot())
    }
    @Test fun negativeRepeatIsRejected() {
        try {
            KeyboardCaptureCounters().observe(0, false, -1, false)
            fail("Negative repeat accepted")
        } catch (_: IllegalArgumentException) { }
    }
}
