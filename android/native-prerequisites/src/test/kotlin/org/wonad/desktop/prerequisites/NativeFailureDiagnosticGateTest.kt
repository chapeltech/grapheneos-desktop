package org.wonad.desktop.prerequisites

import org.junit.Assert.*
import org.junit.Test

class NativeFailureDiagnosticGateTest {
    private val run = "a".repeat(32)

    @Test fun exactAcknowledgementIsOneShotAndCannotExtendTheDeadline() {
        var now = 100L
        val gate = NativeFailureDiagnosticGate(run,"direct",2220) { now }
        assertFalse(gate.acknowledge(NativeFailureDiagnosticGate.ACTION,run,"direct",2220,NativeFailureDiagnosticGate.STEP))
        gate.begin()
        assertEquals(30000L,gate.remainingMillis())
        now = 200
        assertTrue(gate.acknowledge(NativeFailureDiagnosticGate.ACTION,run,"direct",2220,NativeFailureDiagnosticGate.STEP))
        assertFalse(gate.acknowledge(NativeFailureDiagnosticGate.ACTION,run,"direct",2220,NativeFailureDiagnosticGate.STEP))
        assertEquals(0L,gate.remainingMillis())
        val closed=gate.close()
        assertEquals(30100L,closed.deadline)
        assertEquals(200L,closed.acknowledgedAt)
        now = 400
        assertEquals(closed,gate.close())
    }

    @Test fun wrongNonceModePidActionOrStepDoesNotAcknowledgeOrDelayCleanup() {
        val gate = NativeFailureDiagnosticGate(run,"direct",2220) { 100L }
        gate.begin()
        for (values in listOf(
            listOf("foreign",run,"direct",2220,NativeFailureDiagnosticGate.STEP),
            listOf(NativeFailureDiagnosticGate.ACTION,"b".repeat(32),"direct",2220,NativeFailureDiagnosticGate.STEP),
            listOf(NativeFailureDiagnosticGate.ACTION,run,"abi",2220,NativeFailureDiagnosticGate.STEP),
            listOf(NativeFailureDiagnosticGate.ACTION,run,"direct",2221,NativeFailureDiagnosticGate.STEP),
            listOf(NativeFailureDiagnosticGate.ACTION,run,"direct",2220,"direct-ready")
        )) assertFalse(gate.acknowledge(values[0] as String,values[1] as String,values[2] as String,
            values[3] as Int,values[4] as String))
        assertEquals(30000L,gate.remainingMillis())
        assertNull(gate.close().acknowledgedAt)
        assertFalse(gate.acknowledge(NativeFailureDiagnosticGate.ACTION,run,"direct",2220,NativeFailureDiagnosticGate.STEP))
    }

    @Test fun deadlineOrLateAckAlwaysClosesWithoutAReadinessRetry() {
        for (late in listOf(30100L,30101L,Long.MAX_VALUE)) {
            var now=100L
            val gate=NativeFailureDiagnosticGate(run,"direct",2220) { now }
            gate.begin(); now=late
            assertEquals(0L,gate.remainingMillis())
            assertFalse(gate.acknowledge(NativeFailureDiagnosticGate.ACTION,run,"direct",2220,NativeFailureDiagnosticGate.STEP))
            assertNull(gate.close().acknowledgedAt)
        }
    }
}
