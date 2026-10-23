package org.wonad.desktop.transitionfault

import org.junit.Assert.*
import org.junit.Test

class NativeCompletionScopeTest {
    private val owner = Any()
    private val binders = listOf(Any(), Any())
    private val uids = intArrayOf(10042, 10042)
    private val current = longArrayOf(42, 7, 9, 1, 2,
        50, 3, 0, 0, 1000, 700, 160, 1, 42,
        10, 50, 3, 3, 497, 697, 1, 1, 1, 1, 1, 0,
        11, 50, 503, 3, 997, 697, 1, 1, 1, 1, 1, 1)
    private val desired = longArrayOf(42, 7, 9, 0, 0, 2, 0,
        10, 50, 3, 3, 997, 347, 1, 1, 0,
        11, 50, 3, 353, 997, 697, 1, 1, 1)
    private fun capture(current: LongArray = this.current, desired: LongArray = this.desired,
        owner: Any = this.owner, binders: List<Any> = this.binders, uids: IntArray = this.uids) =
        NativeCompletionScope.capture(0, 42, owner, binders, uids, current, desired, 10042, setOf(50), setOf(10, 11))
    private fun matches(scope: NativeCompletionScope, owner: Any = this.owner,
        binders: List<Any> = this.binders, uids: IntArray = this.uids,
        current: LongArray = this.current, desired: LongArray = this.desired) =
        scope.matches(0, 42, owner, binders, uids, current, desired)

    @Test fun exactActualPayloadMatches() { assertTrue(matches(requireNotNull(capture()))) }
    @Test fun foreignOwnerBinderCannotMatch() { assertFalse(matches(requireNotNull(capture()), owner = Any())) }
    @Test fun replacedTaskBinderCannotMatchEvenAtSameScalarToken() { assertFalse(matches(requireNotNull(capture()), binders = listOf(binders[0], Any()))) }
    @Test fun binderOrderCannotBePermuted() { assertFalse(matches(requireNotNull(capture()), binders = binders.reversed())) }
    @Test fun uidChangesNeverMatch() { assertFalse(matches(requireNotNull(capture()), uids = intArrayOf(10042, 10043))) }
    @Test fun generationAndUserChangesNeverMatch() {
        val scope = requireNotNull(capture())
        assertFalse(scope.matches(0, 43, owner, binders, uids, current, desired))
        assertFalse(scope.matches(10, 42, owner, binders, uids, current, desired))
    }
    @Test fun topologyOrRevisionChangesNeverMatch() {
        val scope = requireNotNull(capture())
        assertFalse(matches(scope, current = current.copyOf().apply { this[2]++ }))
        assertFalse(matches(scope, desired = desired.copyOf().apply { this[1]++ }))
    }
    @Test fun captureRejectsWrongNativeGeneration() { assertNull(capture(current = current.copyOf().apply { this[0]++ })) }
    @Test fun captureRejectsInsecureUnreadyAndPhoneDisplays() {
        for (index in listOf(6, 12, 13)) assertNull(capture(current = current.copyOf().apply { this[index] = 0 }))
    }
    @Test fun captureRejectsUnknownOrDuplicatedNativeTasks() {
        assertNull(capture(current = current.copyOf().apply { this[14] = 12 }))
        assertNull(capture(desired = desired.copyOf().apply { this[16] = 10 }))
    }
    @Test fun captureRejectsPhoneDestinationOrUnexpectedShellRegions() {
        assertNull(capture(desired = desired.copyOf().apply { this[8] = 0 }))
        assertNull(capture(desired = desired.copyOf().apply { this[6] = 1 }))
    }
    @Test fun captureRejectsHiddenOrNonInputApplications() {
        assertNull(capture(current = current.copyOf().apply { this[23] = 0 }))
        assertNull(capture(desired = desired.copyOf().apply { this[14] = 0 }))
    }
    @Test fun captureRejectsTruncatedAndOversizedWire() {
        assertNull(capture(current = current.copyOf(current.size - 1)))
        assertNull(capture(desired = desired.copyOf(desired.size + 1)))
    }
    @Test fun captureRejectsForeignUidsAndDuplicatedBinders() {
        assertNull(capture(uids = intArrayOf(10042, 10043)))
        assertNull(capture(binders = listOf(binders[0], binders[0])))
    }
    @Test fun mutableCallerArraysAndExportedCopiesCannotRetargetScope() {
        val originalCurrent = current.copyOf(); val originalDesired = desired.copyOf(); val originalUids = uids.copyOf()
        val scope = requireNotNull(capture())
        current[0] = 99; desired[0] = 99; uids[0] = 10043
        scope.current[0] = 0; scope.desired[0] = 0
        assertTrue(matches(scope, current = originalCurrent, desired = originalDesired, uids = originalUids))
        assertFalse(matches(scope))
    }
}
