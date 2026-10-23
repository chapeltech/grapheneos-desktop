package org.wonad.desktop

import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/** Attempt every original facade cleanup step; fatal errors keep precedence. */
internal object ConformanceShellRetirement {
    fun preserve(primary: Throwable?, error: Throwable): Throwable {
        if (primary == null || primary === error) return error
        val primaryFatal = primary !is Exception && primary !is LinkageError
        val errorFatal = error !is Exception && error !is LinkageError
        return if (errorFatal && !primaryFatal) error.also { it.addSuppressed(primary) }
        else primary.also { it.addSuppressed(error) }
    }

    fun complete(vararg actions: () -> Unit) {
        var failure: Throwable? = null
        actions.forEach { action ->
            try { action() } catch (error: Throwable) { failure = preserve(failure, error) }
        }
        failure?.let { throw it }
    }
}

/** Process-local expectations let the fixed Activities reject stale or forged
 * launches without receiving any Android handle from the broker. */
internal object ConformanceRegistry {
    data class DisplayClaim(val generation: Long, val token: Long, val displayId: Int)
    data class LauncherClaim(val generation: Long, val catalogId: Long, val displayId: Int)
    data class FacadeEvent(val name: String, val valid: Boolean, val displayId: Int)

    @Volatile var ledger: ConformanceStatus? = null
        private set
    private val lock = Any()
    private var displays = emptyMap<Long, DisplayClaim>()
    private var launcher: LauncherClaim? = null
    private class ShellOwner(val claim: DisplayClaim, val retire: () -> Unit)
    private val shells = mutableListOf<ShellOwner>()
    private val events = LinkedBlockingQueue<FacadeEvent>(64)

    fun begin(value: ConformanceStatus) {
        displays(0, emptyList())
        synchronized(lock) { ledger = value; launcher = null; events.clear() }
    }
    fun displays(generation: Long, values: List<Pair<Long, Int>>) {
        val retired = synchronized(lock) {
            displays = values.associate { (token, display) -> token to DisplayClaim(generation, token, display) }
            shells.filter { displays[it.claim.token] != it.claim }.also { shells.removeAll(it.toSet()) }
        }
        // Authority is withdrawn before dispatch, outside the registry lock.
        // Each callback owns one original Activity, never a replacement token.
        ConformanceShellRetirement.complete(*retired.map { owner -> owner.retire }.toTypedArray())
    }
    fun ownShell(claim: DisplayClaim, retire: () -> Unit): AutoCloseable {
        val owner = ShellOwner(claim, retire)
        synchronized(lock) {
            check(displays[claim.token] == claim) { "shell claim retired before registration" }
            shells.add(owner)
        }
        return AutoCloseable { synchronized(lock) { shells.remove(owner); Unit } }
    }
    fun display(token: Long): DisplayClaim? = synchronized(lock) { displays[token] }
    fun expectedDisplay(displayId: Int): Boolean = synchronized(lock) { displays.values.any { it.displayId == displayId } }
    fun launcher(value: LauncherClaim?) = synchronized(lock) { launcher = value }
    fun launcher(): LauncherClaim? = synchronized(lock) { launcher }
    fun record(name: String, valid: Boolean, displayId: Int) {
        ledger?.facade(name, valid)
        val value = FacadeEvent(name, valid, displayId)
        if (!events.offer(value)) { events.poll(); events.offer(value) }
    }
    fun await(name: String, timeoutMillis: Long, valid: Boolean = true): FacadeEvent {
        val deadline = android.os.SystemClock.elapsedRealtime() + timeoutMillis
        while (android.os.SystemClock.elapsedRealtime() < deadline) {
            val remaining = deadline - android.os.SystemClock.elapsedRealtime()
            val event = events.poll(remaining.coerceAtLeast(1), TimeUnit.MILLISECONDS)
                ?: break
            if (event.name == name && event.valid == valid) return event
        }
        error("No $name facade event")
    }
    fun clear() {
        try { displays(0, emptyList()) }
        finally { synchronized(lock) { launcher = null; events.clear(); ledger = null } }
    }
}
