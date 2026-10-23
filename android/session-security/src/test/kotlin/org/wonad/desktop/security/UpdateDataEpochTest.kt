package org.wonad.desktop.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class UpdateDataEpochTest {
    private fun stat(pid: Int = 123, start: Long = 456, state: String = "S", ticks: Long = 7): String {
        val fields = MutableList(19) { "1" }
        fields[10] = ticks.toString(); fields[11] = (ticks + 1).toString(); fields[18] = start.toString()
        return "$pid (app (worker)) $state ${fields.joinToString(" ")}\n"
    }
    @Test fun actualEpochDoesNotCompareAdvancingCpuTicksOrState() {
        assertEquals(456L, UpdateDataEpoch.verified(stat(), stat(state = "R", ticks = 20), 123))
    }
    @Test fun changedPidIsNotSameIncarnation() {
        assertThrows(IllegalStateException::class.java) { UpdateDataEpoch.verified(stat(), stat(pid = 124), 123) }
    }
    @Test fun reusedPidWithChangedStartIsNotSameIncarnation() {
        assertThrows(IllegalStateException::class.java) { UpdateDataEpoch.verified(stat(), stat(start = 457), 123) }
    }
    @Test fun zeroStartIsNotObservedIncarnation() {
        assertThrows(IllegalStateException::class.java) { UpdateDataEpoch.startTicks(stat(start = 0), 123) }
    }
    @Test fun malformedTruncatedStatFails() {
        assertThrows(IllegalStateException::class.java) { UpdateDataEpoch.startTicks("123 (app) R 1\n", 123) }
    }
    @Test fun multilineStatFails() {
        assertThrows(IllegalStateException::class.java) { UpdateDataEpoch.startTicks(stat() + "another line\n", 123) }
    }
}
