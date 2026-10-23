package org.wonad.desktop.broker

import java.util.concurrent.FutureTask
import org.junit.Assert.*
import org.junit.Test

class BrokerDispatchTest {
    @Test fun everyOwnedCleanupRunsAndAllFailuresRemainObservable() {
        val ticket = IllegalStateException("ticket cancellation failed")
        val ui = IllegalStateException("UI invalidation failed")
        val attempted = mutableListOf<Int>()
        try {
            runBrokerCleanup(
                { attempted.add(1); throw ticket },
                { attempted.add(2); throw ui },
                { attempted.add(3) },
            )
            fail("Standalone cleanup must report failure")
        } catch (error: IllegalStateException) {
            assertSame(ticket, error)
            assertSame(ui, error.suppressed.single())
        }
        assertEquals(listOf(1, 2, 3), attempted)
    }

    @Test fun doubleFailurePreservesOriginalAdmissionException() {
        val denied = SecurityException("original denial")
        val failed = IllegalStateException("cleanup failed")
        preserveBrokerFailure(denied) { throw failed }
        assertSame(failed, denied.suppressed.single())
    }

    @Test fun cleanupDoesNotAttemptToSuppressTheSameExceptionTwice() {
        val failure = IllegalStateException("shared failure object")
        var released = false
        preserveBrokerFailure(failure) {
            runBrokerCleanup({ throw failure }, { throw failure }, { released = true })
        }
        assertTrue(released)
        assertEquals(0, failure.suppressed.size)
    }

    @Test fun linkageFailureDoesNotSkipIndependentCleanup() {
        var released = false
        val missing = UnsatisfiedLinkError("native cancellation unavailable")
        try {
            runBrokerCleanup({ throw missing }, { released = true })
            fail("Linkage failure must remain observable")
        } catch (error: UnsatisfiedLinkError) { assertSame(missing, error) }
        assertTrue(released)
    }

    @Test fun safeAdmissionReasonSurvivesWithoutAnInternalStackCause() {
        val task = FutureTask<Int> { throw BrokerAdmissionException("No eligible external display") }.also { it.run() }
        try {
            awaitBrokerResult(task, 100) { fail("Completed rejection is not cancellation") }
            fail("Expected admission rejection")
        } catch (error: IllegalStateException) {
            assertEquals("No eligible external display", error.message)
            assertNull(error.cause)
        }
    }
    @Test fun successDoesNotCancelOrReconcile() {
        val task = FutureTask { 42 }.also { it.run() }
        assertEquals(42, awaitBrokerResult(task, 100) { fail("Unexpected cancellation") })
        assertFalse(task.isCancelled)
    }

    @Test fun actualSecurityDenialRetainsItsTypeAndIdentity() {
        val denied = SecurityException("Caller is not the Wonad package")
        val task = FutureTask<Int> { throw denied }.also { it.run() }
        try {
            awaitBrokerResult(task, 100) { fail("Authorization denial is not cancellation") }
            fail("Expected SecurityException")
        } catch (error: SecurityException) { assertSame(denied, error) }
        assertFalse(task.isCancelled)
    }

    @Test fun unrelatedFailureIsNotReportedAsAuthorizationDenial() {
        val failed = UnsupportedOperationException("platform failure")
        val task = FutureTask<Int> { throw failed }.also { it.run() }
        try {
            awaitBrokerResult(task, 100) { fail("Completed failure is not cancellation") }
            fail("Expected failure")
        } catch (error: IllegalStateException) {
            assertEquals("Broker operation failed", error.message)
            assertSame(failed, error.cause)
        }
    }

    @Test fun timeoutCancelsUndispatchedWorkAndReconcilesOnce() {
        var ran = false
        var reconciled = 0
        val task = FutureTask { ran = true; 42 }
        try {
            awaitBrokerResult(task, 1) { reconciled++ }
            fail("Expected timeout")
        } catch (error: IllegalStateException) { assertEquals("Broker did not respond", error.message) }
        task.run()
        assertFalse(ran)
        assertTrue(task.isCancelled)
        assertEquals(1, reconciled)
    }
}
