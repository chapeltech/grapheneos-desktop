package org.wonad.desktop.security

import org.junit.Assert.*
import org.junit.Test

class NativeFrameConstraintSpecTest {
    private val box = listOf(10, 20, 510, 420)
    private val area = listOf(0, 0, 800, 600)
    @Test fun usesActualAppMinimumOnly() {
        assertEquals("minimum_width" to listOf(10, 20, 109, 420), NativeFrameConstraintSpec.impossible(box, 100, 80, true, area))
        assertEquals("minimum_height" to listOf(10, 20, 510, 99), NativeFrameConstraintSpec.impossible(box, 0, 80, true, area))
        assertNull(NativeFrameConstraintSpec.impossible(box, 0, 0, true, area))
        assertNull(NativeFrameConstraintSpec.impossible(box, 1, 1, true, area))
    }
    @Test fun changesGenuineFixedSizeWithoutLeavingMonitor() {
        assertEquals("nonresizable_width" to listOf(10, 20, 509, 420), NativeFrameConstraintSpec.impossible(box, 0, 0, false, area))
        assertEquals("nonresizable_width" to listOf(0, 0, 2, 1), NativeFrameConstraintSpec.impossible(listOf(0, 0, 1, 1), 0, 0, false, area))
        assertNull(NativeFrameConstraintSpec.impossible(listOf(0, 0, 1, 1), 0, 0, false, listOf(0, 0, 1, 1)))
    }
    @Test fun rejectsInventedOrImpossibleExistingMinima() {
        for (minimum in listOf(-1, 501)) {
            try { NativeFrameConstraintSpec.impossible(box, minimum, 0, true, area); fail("Accepted bad app minimum") }
            catch (_: IllegalArgumentException) {}
        }
    }
}
