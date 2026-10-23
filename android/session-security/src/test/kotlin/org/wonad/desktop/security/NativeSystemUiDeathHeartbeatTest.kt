package org.wonad.desktop.security

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.*
import org.junit.Test

class NativeSystemUiDeathHeartbeatTest {
    private class ActualDeadBinder : RuntimeException()
    private fun rejected(block: () -> Unit) {
        try { block(); fail("Accepted false heartbeat/death ordering") } catch (_: IllegalStateException) {}
    }

    @Test fun actualSequenceContinuesAndDoesNotStopForHostCaptures() {
        val dead = AtomicBoolean(); val seen = mutableListOf<Long>(); val second = CountDownLatch(2)
        val heartbeat = NativeSystemUiDeathHeartbeat(41,
            { synchronized(seen) { seen.add(it) }; second.countDown() }, { dead.get() }, { it is ActualDeadBinder })
        try {
            heartbeat.requireAlive()
            rejected { heartbeat.stopAfterDeath() }
            assertTrue(second.await(2, TimeUnit.SECONDS))
            assertEquals(listOf(42L, 43L), synchronized(seen) { seen.take(2) })
            dead.set(true); heartbeat.stopAfterDeath()
            val size = synchronized(seen) { seen.size }
            heartbeat.close()
            assertEquals(size, synchronized(seen) { seen.size })
        } finally { heartbeat.close() }
    }

    @Test fun onlyActualDeadObjectAfterPositiveDeathCanBeExpected() {
        val dead = AtomicBoolean(); val sent = AtomicInteger(); val failed = CountDownLatch(1)
        val heartbeat = NativeSystemUiDeathHeartbeat(2, {
            if (sent.incrementAndGet() > 1) { failed.countDown(); throw ActualDeadBinder() }
        }, { dead.get() }, { it is ActualDeadBinder })
        heartbeat.requireAlive()
        assertTrue(failed.await(2, TimeUnit.SECONDS))
        rejected { heartbeat.stopAfterDeath() }
        dead.set(true); heartbeat.stopAfterDeath(); heartbeat.close()
    }

    @Test fun genericHeartbeatFailureIsNeverSwallowedByActualDeath() {
        val dead = AtomicBoolean(); val sent = AtomicInteger(); val failed = CountDownLatch(1)
        val heartbeat = NativeSystemUiDeathHeartbeat(7, {
            if (sent.incrementAndGet() > 1) { failed.countDown(); throw SecurityException("wrong owner") }
        }, { dead.get() }, { it is ActualDeadBinder })
        heartbeat.requireAlive(); assertTrue(failed.await(2, TimeUnit.SECONDS)); dead.set(true)
        rejected { heartbeat.stopAfterDeath() }
        rejected { heartbeat.close() }
    }

    @Test fun failedOrAlreadyDeadFirstHeartbeatCannotArmTheProbe() {
        val failed = NativeSystemUiDeathHeartbeat(0, { throw ActualDeadBinder() }, { true }, { it is ActualDeadBinder })
        rejected { failed.requireAlive() }
        rejected { failed.close() }
        val dead = NativeSystemUiDeathHeartbeat(0, {}, { true }, { it is ActualDeadBinder })
        try { rejected { dead.requireAlive() } } finally { dead.close() }
    }

    @Test fun preCrashCleanupCannotLaterCountAsAnActiveLeaseDeath() {
        val dead = AtomicBoolean()
        val heartbeat = NativeSystemUiDeathHeartbeat(4, {}, { dead.get() }, { it is ActualDeadBinder })
        heartbeat.requireAlive(); heartbeat.close(); dead.set(true)
        rejected { heartbeat.stopAfterDeath() }
    }
}
