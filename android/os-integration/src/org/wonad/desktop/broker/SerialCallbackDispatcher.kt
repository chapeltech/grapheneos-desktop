package org.wonad.desktop.broker

import java.util.ArrayDeque
import java.util.concurrent.Executor

/**
 * Bounded, single-consumer delivery for remote Binder callbacks.
 *
 * State is changed under [lock], but callback code is *always* invoked after
 * releasing it.  In particular, marking a generation terminal never waits for
 * a client whose Binder receive queue has stopped draining.  Marking terminal
 * suppresses ordinary events which have not started; the terminal event has
 * one reserved queue position and follows any already in-flight event.
 */
internal class SerialCallbackDispatcher(
    private val executor: Executor,
    private val capacity: Int,
    private val onFailure: (Throwable) -> Unit,
    private val onStarted: (Long) -> Unit = {},
    private val onFinished: (Long) -> Unit = {},
    private val onActive: () -> Unit = {},
    private val onIdle: () -> Unit = {},
) {
    private val lock = Any()
    private val queue = ArrayDeque<() -> Unit>()
    private var worker = false
    private var accepting = true
    private var terminalMarked = false
    private var terminalQueued = false
    private var failureReported = false
    private var nextDelivery = 0L
    private var inFlight = 0L

    init { require(capacity > 0) }

    /** Returns false after the terminal boundary or on bounded saturation. */
    fun offer(event: () -> Unit): Boolean {
        var start = false
        var failure: Throwable? = null
        synchronized(lock) {
            if (!accepting) return false
            if (queue.size >= capacity) {
                accepting = false
                if (!failureReported) {
                    failureReported = true
                    failure = IllegalStateException("Native callback queue full")
                }
            } else {
                queue.addLast(event)
                if (!worker) {
                    worker = true
                    // Publish the worker reservation to the controller before
                    // releasing this lock; replacement admission can never
                    // slip between worker=true and the global barrier.
                    onActive()
                    start = true
                }
            }
        }
        failure?.let(onFailure)
        val started = !start || startWorker()
        return failure == null && started
    }

    /** Closes ordinary submission without waiting for an in-flight callback. */
    fun markTerminal() {
        synchronized(lock) {
            accepting = false
            terminalMarked = true
            // Calls already issued outside the lock cannot be cancelled, but
            // queued snapshots/results/commands become late at this boundary.
            queue.clear()
        }
    }

    /** Queue the one terminal callback after any already in-flight event. */
    fun offerTerminal(event: () -> Unit) {
        var start = false
        synchronized(lock) {
            check(terminalMarked) { "Terminal callback queued before terminal mark" }
            if (terminalQueued) return
            terminalQueued = true
            // Capacity is deliberately not consulted: this is the reserved
            // terminal position, so saturation cannot reorder or omit it.
            queue.addLast(event)
            if (!worker) { worker = true; onActive(); start = true }
        }
        if (start) startWorker()
    }

    /** Used only by the owner watchdog; it neither waits nor runs callbacks. */
    fun isInFlight(delivery: Long): Boolean = synchronized(lock) { inFlight == delivery }

    private fun startWorker(): Boolean = try {
            executor.execute { drain() }
            true
        } catch (error: RuntimeException) {
            transportFailure(error)
            false
        }

    private fun drain() {
        while (true) {
            val delivery = synchronized(lock) {
                if (queue.isEmpty()) {
                    worker = false
                    null
                } else {
                    val token = Math.addExact(nextDelivery, 1L)
                    nextDelivery = token
                    inFlight = token
                    token to queue.removeFirst()
                }
            }
            if (delivery == null) { onIdle(); return }
            try {
                // Cross-process Binder IPC is deliberately outside lock.
                onStarted(delivery.first)
                delivery.second()
            } catch (error: Exception) {
                transportFailure(error)
                return
            } catch (error: LinkageError) {
                transportFailure(error)
                return
            } finally {
                synchronized(lock) {
                    if (inFlight == delivery.first) inFlight = 0
                }
                onFinished(delivery.first)
            }
        }
    }

    private fun transportFailure(error: Throwable) {
        var report = false
        var idle = false
        synchronized(lock) {
            accepting = false
            queue.clear()
            idle = worker
            worker = false
            if (!failureReported) { failureReported = true; report = true }
        }
        if (idle) onIdle()
        if (report) onFailure(error)
    }
}
