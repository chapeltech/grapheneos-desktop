package org.wonad.desktop.security

import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/** Test-only keepalive across a deliberate physical Binder-owner death.
 * The ordinary client's strict heartbeat-error contract remains unchanged.
 */
internal class NativeSystemUiDeathHeartbeat(
    startSequence: Long,
    private val send: (Long) -> Unit,
    private val actualDeath: () -> Boolean,
    private val expectedDeathError: (Throwable) -> Boolean
) : AutoCloseable {
    private val sequence = AtomicLong(startSequence)
    private val failure = AtomicReference<Throwable?>()
    private val first = CountDownLatch(1)
    private val stopped = AtomicBoolean()
    private val deathObserved = AtomicBoolean()
    private val timer = Executors.newSingleThreadScheduledExecutor()

    init {
        require(startSequence >= 0 && startSequence < Long.MAX_VALUE)
        timer.scheduleWithFixedDelay({
            try {
                val next = sequence.updateAndGet { Math.addExact(it, 1L) }
                send(next)
            } catch (error: Throwable) {
                failure.compareAndSet(null, error)
            } finally { first.countDown() }
        }, 0, 500, TimeUnit.MILLISECONDS)
    }

    fun requireAlive() {
        check(!stopped.get() && first.await(2, TimeUnit.SECONDS)) { "No actual pre-crash heartbeat" }
        failure.get()?.let { throw IllegalStateException("Pre-crash heartbeat failed", it) }
        check(!actualDeath()) { "Binder owner already dead before armed phase" }
    }

    fun stopAfterDeath() {
        check(!stopped.get()) { "Heartbeat already stopped before actual death barrier" }
        check(actualDeath()) { "Heartbeat cannot stop before both actual Binder death notifications" }
        deathObserved.set(true)
        close()
    }

    override fun close() {
        if (stopped.compareAndSet(false, true)) {
            timer.shutdownNow()
            check(timer.awaitTermination(2, TimeUnit.SECONDS)) { "Death heartbeat did not terminate" }
        }
        failure.get()?.let { error ->
            check(deathObserved.get() && actualDeath() && expectedDeathError(error)) {
                "Unexpected death heartbeat failure: ${error.javaClass.name}: ${error.message}"
            }
        }
    }
}
