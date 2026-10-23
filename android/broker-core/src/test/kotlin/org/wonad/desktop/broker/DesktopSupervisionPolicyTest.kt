package org.wonad.desktop.broker

import org.junit.Assert.*
import org.junit.Test

class DesktopSupervisionPolicyTest {
    @Test fun crashesBackOffAndNeverSpin() {
        val policy = DesktopSupervisionPolicy()
        var now = 0L
        for (delay in listOf(1000L, 2000L, 4000L, 8000L, 16000L, 30000L, 30000L)) {
            assertTrue(policy.mayStart(now))
            assertEquals(delay, policy.failed(now))
            assertFalse(policy.mayStart(now + delay - 1))
            now += delay
        }
    }
    @Test fun onlySustainedHealthResetsCrashHistory() {
        val policy = DesktopSupervisionPolicy()
        assertEquals(1000L, policy.failed(0))
        policy.connected(1000)
        policy.healthy(60_999)
        assertEquals(2000L, policy.failed(61_000))
        policy.connected(63_000)
        policy.healthy(123_000)
        assertEquals(1000L, policy.failed(123_001))
    }
    @Test fun disableAndIdentityChangeResetStartupEligibility() {
        val policy = DesktopSupervisionPolicy()
        policy.failed(1000)
        assertFalse(policy.mayStart(1500))
        policy.reset()
        assertTrue(policy.mayStart(1500))
    }
}
