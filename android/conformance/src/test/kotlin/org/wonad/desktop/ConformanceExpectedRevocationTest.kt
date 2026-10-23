package org.wonad.desktop

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Pure TEST-client controls, not Android lock/user-transition qualification. */
class ConformanceExpectedRevocationTest {
    private val nonce = "a".repeat(32)
    private val run = "b".repeat(32)

    private fun denied(action: () -> Unit) {
        var failure: Throwable? = null
        try { action() } catch (error: IllegalArgumentException) { failure = error }
        catch (error: IllegalStateException) { failure = error }
        assertTrue("Expected exact expectation denial", failure != null)
    }

    @Test fun exactReviewedCallbacksAreOneShotAndNonceBound() {
        for (reason in listOf(3, 4, 5)) {
            val gate = ConformanceExpectedRevocation { 10L }
            gate.arm(nonce, RuntimeRevocationRequest(101, 201, reason), 101, 201)
            assertTrue(gate.json().contains("\"state\":\"armed\""))
            assertTrue(gate.consume(101, 201, 101, reason))
            assertTrue(gate.json().contains("\"state\":\"consumed\""))
            assertFalse(gate.consume(101, 201, 101, reason))
            denied { gate.arm(nonce, RuntimeRevocationRequest(101, 201, reason), 101, 201) }
        }
    }

    @Test fun wrongNextCallbackConsumesExpectationButNeverAdmitsRecovery() {
        for ((currentGeneration, epoch, callbackGeneration, reason) in listOf(
            listOf(102L, 201L, 101L, 3L), listOf(101L, 202L, 101L, 3L),
            listOf(101L, 201L, 102L, 3L), listOf(101L, 201L, 101L, 4L),
            listOf(101L, 201L, 101L, 5L))) {
            val gate = ConformanceExpectedRevocation { 10L }
            gate.arm(nonce, RuntimeRevocationRequest(101, 201, 3), 101, 201)
            denied { gate.consume(currentGeneration, epoch, callbackGeneration, reason.toInt()) }
            assertFalse(gate.consume(101, 201, 101, 3))
            assertEquals("null", gate.json())
        }
    }

    @Test fun exactDeadlineIsBoundedAndBackwardsClockFails() {
        for (invalid in listOf(9L, 120011L)) {
            var now = 10L
            val gate = ConformanceExpectedRevocation { now }
            gate.arm(nonce, RuntimeRevocationRequest(101, 201, 3), 101, 201)
            now = invalid
            denied { gate.consume(101, 201, 101, 3) }
        }
        var now = 10L
        val gate = ConformanceExpectedRevocation { now }
        gate.arm(nonce, RuntimeRevocationRequest(101, 201, 3), 101, 201)
        now = 120010L
        assertTrue(gate.consume(101, 201, 101, 3))
    }

    @Test fun staleOwnerUnreviewedReasonAndConcurrentArmAreRejected() {
        for (reason in listOf(0, 1, 2, 6)) {
            val gate = ConformanceExpectedRevocation { 10L }
            denied { gate.arm(nonce, RuntimeRevocationRequest(101, 201, reason), 101, 201) }
        }
        val gate = ConformanceExpectedRevocation { 10L }
        denied { gate.arm(nonce, RuntimeRevocationRequest(102, 201, 3), 101, 201) }
        denied { gate.arm(nonce, RuntimeRevocationRequest(101, 202, 3), 101, 201) }
        gate.arm(nonce, RuntimeRevocationRequest(101, 201, 3), 101, 201)
        denied { gate.arm("c".repeat(32), RuntimeRevocationRequest(101, 201, 3), 101, 201) }
        gate.cancelPending()
        assertFalse(gate.consume(101, 201, 101, 3))
        denied { gate.arm(nonce, RuntimeRevocationRequest(101, 201, 3), 101, 201) }
    }

    @Test fun hostTupleRequiresExactSevenFieldsAndCanonicalPositiveIntegers() {
        val prefix = arrayOf("runtime-command", run, nonce)
        val valid = prefix + arrayOf("expect-revocation", "101", "201", "3")
        assertEquals(RuntimeRevocationRequest(101, 201, 3), RuntimeHostInstruction.parse(valid).revocation)
        assertEquals(RuntimeRevocationRequest(101, 201, 5), RuntimeHostInstruction.parse(
            prefix + arrayOf("expect-revocation", "101", "201", "5")).revocation)
        assertEquals(null, RuntimeHostInstruction.parse(prefix + "checkpoint").revocation)
        for (fields in listOf(arrayOf("expect-revocation"),
            arrayOf("expect-revocation", "0101", "201", "3"),
            arrayOf("expect-revocation", "101", "201", "6"),
            arrayOf("expect-revocation", "101", "201", "05"),
            arrayOf("expect-revocation", "9999999999999999999999", "201", "3"),
            arrayOf("checkpoint", "101", "201", "3"))) {
            denied { RuntimeHostInstruction.parse(prefix + fields) }
        }
    }

    @Test fun plannedClientFailureDoesNotAdmitOtherCallbacksOrStaleOwners() {
        for (reason in listOf(1, 2, 3, 4, 6)) {
            val gate = ConformanceExpectedRevocation { 10L }
            gate.arm(nonce, RuntimeRevocationRequest(101, 201, 5), 101, 201)
            denied { gate.consume(101, 201, 101, reason) }
            assertFalse(gate.consume(101, 201, 101, 5))
        }
        val gate = ConformanceExpectedRevocation { 10L }
        gate.arm(nonce, RuntimeRevocationRequest(101, 201, 5), 101, 201)
        denied { gate.consume(101, 202, 101, 5) }
    }

    @Test fun plannedClientFailureCannotSurviveDeadlineOrTerminalCleanup() {
        var now = 10L
        val expired = ConformanceExpectedRevocation { now }
        expired.arm(nonce, RuntimeRevocationRequest(101, 201, 5), 101, 201)
        now = 120011L
        denied { expired.consume(101, 201, 101, 5) }
        val retired = ConformanceExpectedRevocation { 10L }
        retired.arm(nonce, RuntimeRevocationRequest(101, 201, 5), 101, 201)
        retired.cancelPending()
        assertFalse(retired.consume(101, 201, 101, 5))
        denied { retired.arm(nonce, RuntimeRevocationRequest(101, 201, 5), 101, 201) }
    }
}
