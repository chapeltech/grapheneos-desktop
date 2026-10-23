package org.wonad.desktop.security

import org.junit.Assert.assertThrows
import org.junit.Test

class NativeProbeContinuityTest {
    private val original = NativeProbeContinuity(100, 200, setOf(10, 11))
    @Test fun freshGenerationAndSameExactTaskNamespaceRecovers() = original.requireRecovery(101, 200, listOf(11, 10))
    @Test fun revokedGenerationCannotBeReused() { assertThrows(IllegalStateException::class.java) { original.requireRecovery(100, 200, listOf(10, 11)) } }
    @Test fun zeroGenerationCannotBeAccepted() { assertThrows(IllegalStateException::class.java) { original.requireRecovery(0, 200, listOf(10, 11)) } }
    @Test fun systemServerRestartIsNotExactTaskContinuity() { assertThrows(IllegalStateException::class.java) { original.requireRecovery(101, 201, listOf(10, 11)) } }
    @Test fun recycledAndroidTaskIdCannotSubstituteANewOpaqueToken() { assertThrows(IllegalStateException::class.java) { original.requireRecovery(101, 200, listOf(10, 12)) } }
    @Test fun missingTaskFailsClosed() { assertThrows(IllegalStateException::class.java) { original.requireRecovery(101, 200, listOf(10)) } }
    @Test fun duplicateTaskFailsEvenIfSetEqualityWouldPass() { assertThrows(IllegalStateException::class.java) { original.requireRecovery(101, 200, listOf(10, 11, 11)) } }
    @Test fun nonpositiveCapturedAuthorityIsRejected() { assertThrows(IllegalArgumentException::class.java) { NativeProbeContinuity(100, 200, setOf(0)) } }
    @Test fun emptyCaptureCannotProveTaskIsolation() { assertThrows(IllegalArgumentException::class.java) { NativeProbeContinuity(100, 200, emptySet()) } }
    @Test fun oversizedCaptureIsRejected() { assertThrows(IllegalArgumentException::class.java) { NativeProbeContinuity(100, 200, (1L..129L).toSet()) } }
}
