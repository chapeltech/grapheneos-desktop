package org.wonad.desktop.broker

import java.util.concurrent.ExecutionException
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit

/** Explicitly safe, bounded admission status chosen by the OS adapter. */
internal class BrokerAdmissionException(message: String) : IllegalStateException(message.take(768))

/** Attempt every independently owned resource release. Do not let a failed
 * native ticket cancellation leave its trusted UI/callback handle active.
 * Ordinary failures remain observable to the caller after all releases run.
 */
internal fun runBrokerCleanup(vararg actions: () -> Unit) {
    var first: Throwable? = null
    for (action in actions) {
        try { action() } catch (error: Throwable) {
            if (error !is Exception && error !is LinkageError) throw error
            val previous = first
            if (previous == null) first = error
            else if (previous !== error) previous.addSuppressed(error)
        }
    }
    first?.let { throw it }
}

/** A teardown failure must not replace the admission/authorization error that
 * caused it. Retain secondary failures without claiming cleanup succeeded.
 */
internal fun preserveBrokerFailure(primary: Throwable, cleanup: () -> Unit) {
    try { cleanup() } catch (error: Throwable) {
        if (error !is Exception && error !is LinkageError) throw error
        if (primary !== error) primary.addSuppressed(error)
    }
}

/** Observe only the failures that this optional privileged extension can
 * recover from. Kotlin's runCatching also consumes VirtualMachineError,
 * ThreadDeath and assertions, which must retain their normal process-level
 * semantics rather than being mistaken for an absent platform capability. */
internal inline fun attemptBrokerOperation(action: () -> Unit): Throwable? = try {
    action()
    null
} catch (error: Throwable) {
    if (error !is Exception && error !is LinkageError) throw error
    error
}

internal inline fun <T> brokerValueOrNull(action: () -> T): T? = try {
    action()
} catch (error: Throwable) {
    if (error !is Exception && error !is LinkageError) throw error
    null
}

/** Keep an executor-owned result even when FutureTask.cancel(false) wins after
 * the operation has started. FutureTask then discards the return value, but a
 * newly minted session must not outlive the caller that never received it.
 * Both task.run() and abandon() MUST execute on the same serial executor.
 */
internal class BrokerDispatch<T>(private val onAbandoned: (T) -> Unit = {}, action: () -> T) {
    private class Outcome<T>(val value: T)
    private var outcome: Outcome<T>? = null
    val task = FutureTask<T> { action().also { outcome = Outcome(it) } }

    fun abandon() {
        val completed = outcome ?: return // Cancelled before dispatch: no side effects.
        outcome = null // Cleanup is one-shot even if it triggers another callback.
        onAbandoned(completed.value)
    }
}

/** Preserve an actual authorization denial across the Shell executor boundary.
 * A timeout or unrelated failure must never masquerade as a successful denial.
 */
internal fun <T> awaitBrokerResult(task: FutureTask<T>, timeoutMillis: Long, onCancelled: () -> Unit): T {
    return try {
        task.get(timeoutMillis, TimeUnit.MILLISECONDS)
    } catch (error: ExecutionException) {
        val cause = error.cause
        if (cause is SecurityException) throw cause
        if (cause is BrokerAdmissionException) throw IllegalStateException(cause.message)
        if (cause is Error && cause !is LinkageError) throw cause
        throw IllegalStateException("Broker operation failed", cause ?: error)
    } catch (error: Exception) {
        // get() can time out just before the executor publishes its result.
        // cancel(false) then returns false, but the caller still did not receive
        // that result. Queue cleanup in either case; BrokerDispatch retains the
        // exact outcome and serial execution keeps cleanup after the operation.
        task.cancel(false)
        onCancelled()
        if (error is InterruptedException) Thread.currentThread().interrupt()
        throw IllegalStateException("Broker did not respond", error)
    }
}
