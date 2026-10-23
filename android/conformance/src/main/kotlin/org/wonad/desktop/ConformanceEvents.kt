package org.wonad.desktop

import android.os.SystemClock
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.wonad.desktop.api.DesktopSnapshot
import org.wonad.desktop.api.IDesktopCallback

internal class ConformanceEvents(private val ledger: ConformanceStatus) : IDesktopCallback.Stub() {
    data class Command(val generation: Long, val command: Int, val argument: Int,
        val taskToken: Long, val displayToken: Long)
    data class Result(val generation: Long, val request: Long, val result: Int, val revision: Long)
    data class Revocation(val generation: Long, val reason: Int)

    private val latest = AtomicReference<DesktopSnapshot?>()
    private val snapshots = LinkedBlockingQueue<DesktopSnapshot>(64)
    private val commands = LinkedBlockingQueue<Command>(16)
    private val results = LinkedBlockingQueue<Result>(32)
    private val revocations = LinkedBlockingQueue<Revocation>(8)

    private fun <T> bounded(queue: LinkedBlockingQueue<T>, value: T) {
        if (!queue.offer(value)) { queue.poll(); check(queue.offer(value)) }
    }
    override fun onSnapshot(snapshot: DesktopSnapshot) {
        latest.set(snapshot); bounded(snapshots, snapshot); ledger.callback("onSnapshot")
    }
    override fun onCommand(generation: Long, command: Int, argument: Int,
        taskToken: Long, displayToken: Long) {
        bounded(commands, Command(generation, command, argument, taskToken, displayToken))
        ledger.callback("onCommand")
    }
    override fun onResult(generation: Long, requestId: Long, result: Int, revision: Long) {
        bounded(results, Result(generation, requestId, result, revision)); ledger.callback("onResult")
    }
    override fun onRevoked(generation: Long, reason: Int) {
        bounded(revocations, Revocation(generation, reason)); ledger.callback("onRevoked")
    }

    fun awaitSnapshot(label: String, timeoutMillis: Long = 20_000,
        predicate: (DesktopSnapshot) -> Boolean): DesktopSnapshot {
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        while (SystemClock.elapsedRealtime() < deadline) {
            latest.get()?.takeIf(predicate)?.let { return it }
            val remaining = deadline - SystemClock.elapsedRealtime()
            snapshots.poll(remaining.coerceAtMost(250).coerceAtLeast(1), TimeUnit.MILLISECONDS)
        }
        error("Timed out waiting for snapshot: $label")
    }
    fun awaitCommand(timeoutMillis: Long = 60_000): Command =
        checkNotNull(commands.poll(timeoutMillis, TimeUnit.MILLISECONDS)) { "No shortcut callback" }
    fun latestSnapshot(): DesktopSnapshot? = latest.get()
    fun pollSnapshot(timeoutMillis: Long): DesktopSnapshot? =
        snapshots.poll(timeoutMillis, TimeUnit.MILLISECONDS)
    fun awaitResult(request: Long, timeoutMillis: Long = 20_000): Result {
        val deadline = SystemClock.elapsedRealtime() + timeoutMillis
        while (SystemClock.elapsedRealtime() < deadline) {
            val event = results.poll((deadline - SystemClock.elapsedRealtime()).coerceAtLeast(1), TimeUnit.MILLISECONDS)
                ?: break
            if (event.request == request) return event
        }
        error("No result callback for request $request")
    }
    fun pollResult(timeoutMillis: Long): Result? =
        results.poll(timeoutMillis, TimeUnit.MILLISECONDS)
    fun awaitRevocation(timeoutMillis: Long = 10_000): Revocation =
        checkNotNull(revocations.poll(timeoutMillis, TimeUnit.MILLISECONDS)) { "No revocation callback" }
    fun pollRevocation(): Revocation? = revocations.poll()
    fun pollRevocation(timeoutMillis: Long): Revocation? =
        revocations.poll(timeoutMillis, TimeUnit.MILLISECONDS)
}
