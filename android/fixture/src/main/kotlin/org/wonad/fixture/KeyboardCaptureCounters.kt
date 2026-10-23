package org.wonad.fixture

/** Bounded aggregate callbacks only. No key code, character, text or event history is retained. */
class KeyboardCaptureCounters(private val limit: Int = LIMIT) {
    init { require(limit in 1..LIMIT) }

    data class Snapshot(val downs: Int, val ups: Int, val otherActions: Int,
        val escapeDowns: Int, val escapeUps: Int, val repeats: Int,
        val canceled: Int, val saturated: Boolean)

    private var downs = 0
    private var ups = 0
    private var otherActions = 0
    private var escapeDowns = 0
    private var escapeUps = 0
    private var repeats = 0
    private var canceled = 0
    private var saturated = false

    private fun increment(value: Int): Int {
        if (value < limit) return value + 1
        saturated = true
        return limit
    }

    @Synchronized fun observe(action: Int, escape: Boolean, repeat: Int, isCanceled: Boolean) {
        require(repeat >= 0)
        when (action) {
            DOWN -> {
                downs = increment(downs)
                if (escape) escapeDowns = increment(escapeDowns)
            }
            UP -> {
                ups = increment(ups)
                if (escape) escapeUps = increment(escapeUps)
            }
            else -> otherActions = increment(otherActions)
        }
        if (repeat > 0) repeats = increment(repeats)
        if (isCanceled) canceled = increment(canceled)
    }

    @Synchronized fun snapshot() = Snapshot(downs, ups, otherActions, escapeDowns,
        escapeUps, repeats, canceled, saturated)

    @Synchronized fun clear() {
        downs = 0; ups = 0; otherActions = 0; escapeDowns = 0; escapeUps = 0
        repeats = 0; canceled = 0; saturated = false
    }

    companion object {
        const val LIMIT = 1_000_000
        const val DOWN = 0
        const val UP = 1
    }
}
