package org.wonad.desktop

import org.junit.After
import org.junit.Assert.*
import org.junit.Test

class ConformanceShellRetirementTest {
    @After fun clear() { ConformanceRegistry.clear() }

    @Test fun unchangedClaimDoesNotRetireOnPublication() {
        ConformanceRegistry.displays(7, listOf(1L to 2))
        var retired = 0
        val owner = ConformanceRegistry.ownShell(ConformanceRegistry.DisplayClaim(7, 1, 2)) { retired++ }
        repeat(3) { ConformanceRegistry.displays(7, listOf(1L to 2)) }
        assertEquals(0, retired)
        owner.close()
    }

    @Test fun newGenerationRetiresOnlyOriginalOwnerOnce() {
        ConformanceRegistry.displays(7, listOf(1L to 2))
        var old = 0; var replacement = 0
        val original = ConformanceRegistry.ownShell(ConformanceRegistry.DisplayClaim(7, 1, 2)) { old++ }
        ConformanceRegistry.displays(8, listOf(1L to 2))
        val fresh = ConformanceRegistry.ownShell(ConformanceRegistry.DisplayClaim(8, 1, 2)) { replacement++ }
        original.close()
        ConformanceRegistry.displays(8, listOf(1L to 2))
        assertEquals(1, old); assertEquals(0, replacement)
        fresh.close()
    }

    @Test fun delayedCallbackCannotSelectReplacementByToken() {
        ConformanceRegistry.displays(7, listOf(1L to 2))
        val pending = mutableListOf<() -> Unit>()
        var oldFinished = false; var freshFinished = false
        ConformanceRegistry.ownShell(ConformanceRegistry.DisplayClaim(7, 1, 2)) { pending.add { oldFinished = true } }
        ConformanceRegistry.displays(8, listOf(1L to 2))
        val fresh = ConformanceRegistry.ownShell(ConformanceRegistry.DisplayClaim(8, 1, 2)) { freshFinished = true }
        pending.single().invoke()
        assertTrue(oldFinished); assertFalse(freshFinished)
        fresh.close()
    }

    @Test fun removedConnectorRetiresOnlyItsExactClaim() {
        ConformanceRegistry.displays(7, listOf(1L to 2, 3L to 4))
        var retired = 0
        ConformanceRegistry.ownShell(ConformanceRegistry.DisplayClaim(7, 1, 2)) { retired++ }
        val keep = ConformanceRegistry.ownShell(ConformanceRegistry.DisplayClaim(7, 3, 4)) { error("current owner retired") }
        ConformanceRegistry.displays(7, listOf(3L to 4))
        assertEquals(1, retired); keep.close()
    }

    @Test fun staleRegistrationIsRejected() {
        ConformanceRegistry.displays(8, listOf(1L to 2))
        try { ConformanceRegistry.ownShell(ConformanceRegistry.DisplayClaim(7, 1, 2)) {} ; fail("stale claim") }
        catch (_: IllegalStateException) { }
    }

    @Test fun failingRetirementStillWithdrawsAllOwners() {
        ConformanceRegistry.displays(7, listOf(1L to 2, 3L to 4))
        val primary = IllegalStateException("original")
        var second = 0
        ConformanceRegistry.ownShell(ConformanceRegistry.DisplayClaim(7, 1, 2)) { throw primary }
        ConformanceRegistry.ownShell(ConformanceRegistry.DisplayClaim(7, 3, 4)) { second++ }
        try { ConformanceRegistry.displays(0, emptyList()); fail("missing failure") }
        catch (error: IllegalStateException) { assertSame(primary, error) }
        assertEquals(1, second); assertNull(ConformanceRegistry.display(1))
        ConformanceRegistry.displays(0, emptyList()); assertEquals(1, second)
    }

    @Test fun actualCleanupBodyAttemptsFinishAndPreservesPrimary() {
        val primary = IllegalStateException("observer removal")
        val secondary = IllegalArgumentException("finish")
        val steps = mutableListOf<String>()
        try {
            ConformanceShellRetirement.complete(
                { steps.add("cancel") },
                { steps.add("withdraw"); throw primary },
                { steps.add("finish"); throw secondary },
            )
            fail("missing failure")
        } catch (error: Throwable) {
            assertSame(primary, error); assertArrayEquals(arrayOf(secondary), error.suppressed)
        }
        assertEquals(listOf("cancel", "withdraw", "finish"), steps)
    }

    @Test fun cancelFailureCannotSkipObserverWithdrawalOrFinish() {
        val primary = IllegalStateException("cancel")
        val steps = mutableListOf<String>()
        try {
            ConformanceShellRetirement.complete(
                { steps.add("cancel"); throw primary }, { steps.add("withdraw") }, { steps.add("finish") },
            )
            fail("missing failure")
        } catch (error: Throwable) { assertSame(primary, error) }
        assertEquals(listOf("cancel", "withdraw", "finish"), steps)
    }

    @Test fun fatalCleanupKeepsExactIdentityAndAttemptsRemainingSteps() {
        val supported = IllegalStateException("supported")
        val fatal = AssertionError("fatal")
        var finished = false
        try {
            ConformanceShellRetirement.complete({ throw supported }, { throw fatal }, { finished = true })
            fail("missing fatal")
        } catch (error: Throwable) {
            assertSame(fatal, error); assertArrayEquals(arrayOf(supported), error.suppressed)
        }
        assertTrue(finished)
    }
}
