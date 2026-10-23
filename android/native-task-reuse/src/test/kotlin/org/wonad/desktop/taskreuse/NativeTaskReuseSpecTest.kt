package org.wonad.desktop.taskreuse
import org.junit.Assert.*
import org.junit.Test

class NativeTaskReuseSpecTest {
    @Test fun realFullRangeHasSameIdAndOneWrap() {
        val cycle = NativeTaskReuseSpec(25)
        for (id in 26..99999) assertFalse(cycle.observed(id))
        for (id in 0..24) assertFalse(cycle.observed(id))
        assertTrue(cycle.observed(25)); assertEquals(100000,cycle.allocations); assertEquals(1,cycle.wraps)
    }
    @Test fun ordinaryNewIdNeverClaimsReuse() { val cycle=NativeTaskReuseSpec(25); assertFalse(cycle.observed(26)) }
    @Test fun shortSameIdAndInvalidIdsAreRejected() {
        for (id in listOf(-1,25,100000)) {
            try { NativeTaskReuseSpec(25).observed(id); fail("accepted $id") } catch(_: IllegalArgumentException) {} catch(_: IllegalStateException) {}
        }
    }
    @Test fun allFourActualNativeMethodsAreRequired() {
        assertEquals(listOf("focusTask","closeTask","applyFrame","applySignedFrame"),NativeTaskReuseSpec.STALE)
    }
}
