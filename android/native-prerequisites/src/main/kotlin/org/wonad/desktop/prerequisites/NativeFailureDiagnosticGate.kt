package org.wonad.desktop.prerequisites

/** Failure-only test handshake. This never polls readiness or grants WM authority. */
internal class NativeFailureDiagnosticGate(
    private val run: String,
    private val mode: String,
    private val ownerPid: Int,
    private val clock: () -> Long
) {
    companion object {
        const val ACTION = "org.wonad.desktop.prerequisites.NEXT"
        const val STEP = "readiness-diagnostic-complete"
        const val WAIT_MS = 30000L
    }
    data class Closed(val started: Long, val deadline: Long, val finished: Long, val acknowledgedAt: Long?)
    private var started: Long? = null
    private var deadline = 0L
    private var acknowledgedAt: Long? = null
    private var closed: Closed? = null

    init {
        require(run.matches(Regex("[0-9a-f]{32}")) && mode == "direct" && ownerPid > 0)
    }

    @Synchronized fun begin() {
        check(started == null && closed == null)
        val now = clock()
        check(now >= 0 && now <= Long.MAX_VALUE - WAIT_MS)
        started = now
        deadline = now + WAIT_MS
    }

    @Synchronized fun acknowledge(action: String?, nonce: String?, observedMode: String?, pid: Int, step: String?): Boolean {
        val first = started ?: return false
        val now = clock()
        if (closed != null || acknowledgedAt != null || now < first || now >= deadline ||
            action != ACTION || nonce != run || observedMode != mode || pid != ownerPid || step != STEP) return false
        acknowledgedAt = now
        return true
    }

    @Synchronized fun remainingMillis(): Long {
        val first = checkNotNull(started)
        if (closed != null || acknowledgedAt != null) return 0
        val now = clock()
        return if (now < first || now >= deadline) 0 else deadline - now
    }

    @Synchronized fun close(): Closed {
        closed?.let { return it }
        return Closed(checkNotNull(started), deadline, clock(), acknowledgedAt).also { closed = it }
    }
}
