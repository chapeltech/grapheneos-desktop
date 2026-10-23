package org.wonad.desktop

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertThrows
import org.junit.Test
import org.wonad.desktop.api.DesktopSnapshot

class ConformancePickerProgressTest {
    private fun snapshot(revision: Long, blocked: Boolean, generation: Long = 41) =
        DesktopSnapshot().also {
            it.generation = generation; it.revision = revision; it.interactionBlocked = blocked
        }

    @Test fun realCallbackDtosRequireFreshBlockedThenFreshUnblockedLauncherObservations() {
        val notifications = mutableListOf<String>()
        val events = ConformanceEvents(object : ConformanceStatus {
            override fun json() = "{}"
            override fun terminalState() = "running"
            override fun callback(name: String) { notifications += name }
            override fun facade(name: String, valid: Boolean) = Unit
        })
        val before = snapshot(12, false)
        events.onSnapshot(before)
        assertFalse(ConformancePickerProgress.opened(
            ConformancePickerProgress.observe(checkNotNull(events.latestSnapshot())), 41, 12))
        events.onSnapshot(snapshot(13, true))
        val opened = checkNotNull(events.latestSnapshot())
        assertTrue(ConformancePickerProgress.opened(ConformancePickerProgress.observe(opened), 41, 12))
        assertTrue(events.awaitSnapshot("fresh catalogue callback") {
            ConformancePickerProgress.opened(ConformancePickerProgress.observe(it), 41, 12)
        } === opened)
        val floor = ConformancePickerProgress.cancellationFloor(
            ConformancePickerProgress.observe(opened), 41, 13)
        assertEquals(13L, floor)
        assertFalse(ConformancePickerProgress.cancelled(ConformancePickerProgress.observe(before), 41, floor))
        assertFalse(ConformancePickerProgress.cancelled(ConformancePickerProgress.observe(opened), 41, floor))
        events.onSnapshot(snapshot(14, false, generation = 42))
        assertFalse(ConformancePickerProgress.cancelled(
            ConformancePickerProgress.observe(checkNotNull(events.latestSnapshot())), 41, floor))
        events.onSnapshot(snapshot(14, false))
        assertTrue(ConformancePickerProgress.cancelled(
            ConformancePickerProgress.observe(checkNotNull(events.latestSnapshot())), 41, floor))
        assertTrue(events.awaitSnapshot("fresh cancellation callback") {
            ConformancePickerProgress.cancelled(ConformancePickerProgress.observe(it), 41, floor)
        } === events.latestSnapshot())
        assertEquals(List(4) { "onSnapshot" }, notifications)
    }

    @Test fun progressRejectsEqualOlderWrongGenerationAndOppositeBlockingState() {
        fun state(revision: Long, blocked: Boolean, gen: Long = 41) =
            ConformancePickerProgress.State(gen, revision, blocked)
        for (value in listOf(state(12, true), state(11, true), state(13, false), state(13, true, 42)))
            assertFalse(ConformancePickerProgress.opened(value, 41, 12))
        for (value in listOf(state(13, false), state(12, false), state(14, true), state(14, false, 42)))
            assertFalse(ConformancePickerProgress.cancelled(value, 41, 13))
        assertFalse(ConformancePickerProgress.opened(state(13, true), 0, 12))
        assertFalse(ConformancePickerProgress.cancelled(state(14, false), 41, 0))
        for (value in listOf(state(12, true), state(14, false), state(14, true, 42))) {
            assertThrows(IllegalStateException::class.java) {
                ConformancePickerProgress.cancellationFloor(value, 41, 13)
            }
        }
    }

    @Test fun cadenceWaitsOnlyTheRemainingIntervalAtEarlyExactAndLateBoundaries() {
        for (initial in listOf(100L, 1_099L, 1_100L, 1_101L)) {
            var now = initial
            val sleeps = mutableListOf<Long>()
            ConformancePickerProgress.awaitCatalogueCadence(100, { now }, { sleeps += it; now += it })
            assertTrue(now >= 1_100)
            assertEquals(maxOf(0L, 1_100L - initial), sleeps.sum())
            assertTrue(sleeps.size <= 10 && sleeps.all { it in 1..100 })
        }
    }

    @Test fun cadenceRejectsNegativeRegressingOverflowedAndFrozenClocks() {
        for (anchor in listOf(-1L, Long.MAX_VALUE - 500)) {
            var clocks = 0; var sleeps = 0
            assertThrows(if (anchor < 0) IllegalStateException::class.java else ArithmeticException::class.java) {
                ConformancePickerProgress.awaitCatalogueCadence(anchor, { clocks++; 0 }, { sleeps++ })
            }
            assertEquals(0, clocks); assertEquals(0, sleeps)
        }
        for (initial in listOf(-1L, 99L)) {
            var sleeps = 0
            assertThrows(IllegalStateException::class.java) {
                ConformancePickerProgress.awaitCatalogueCadence(100, { initial }, { sleeps++ })
            }
            assertEquals(0, sleeps)
        }
        val clock = listOf(150L, 149L).iterator()
        var sleeps = 0
        assertThrows(IllegalStateException::class.java) {
            ConformancePickerProgress.awaitCatalogueCadence(100, { clock.next() }, { sleeps++ })
        }
        assertEquals(1, sleeps)
        sleeps = 0
        assertThrows(IllegalStateException::class.java) {
            ConformancePickerProgress.awaitCatalogueCadence(100, { 100 }, { sleeps++ })
        }
        assertEquals(10, sleeps)
    }

    @Test fun cadencePropagatesInterruptedSleepAndPreservesPreexistingInterruption() {
        val failure = InterruptedException("injected sleep interruption")
        val actual = assertThrows(InterruptedException::class.java) {
            ConformancePickerProgress.awaitCatalogueCadence(100, { 100 }, { throw failure })
        }
        assertTrue(actual === failure)
        var clocks = 0; var sleeps = 0
        Thread.currentThread().interrupt()
        try {
            assertThrows(InterruptedException::class.java) {
                ConformancePickerProgress.awaitCatalogueCadence(100, { clocks++; 100 }, { sleeps++ })
            }
            assertTrue(Thread.currentThread().isInterrupted)
            assertEquals(0, clocks); assertEquals(0, sleeps)
        } finally { Thread.interrupted() }
    }
}
