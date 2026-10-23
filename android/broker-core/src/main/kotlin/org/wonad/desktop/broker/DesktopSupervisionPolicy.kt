package org.wonad.desktop.broker

/** Process lifetime only; never grants a desktop session or chooses a layout. */
internal class DesktopSupervisionPolicy {
    private var failures = 0
    private var retryAt = 0L
    private var connectedAt = -1L

    fun mayStart(now: Long): Boolean = now >= retryAt
    fun connected(now: Long) { connectedAt = now }
    fun healthy(now: Long) {
        if (connectedAt >= 0 && now - connectedAt >= 60_000) failures = 0
    }
    fun failed(now: Long): Long {
        failures = (failures + 1).coerceAtMost(6)
        val delay = (1_000L shl (failures - 1)).coerceAtMost(30_000L)
        retryAt = now + delay
        connectedAt = -1
        return delay
    }
    fun reset() { failures = 0; retryAt = 0; connectedAt = -1 }
}
