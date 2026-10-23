package org.wonad.desktop.prerequisites

/** Test-only bounded evidence. Eviction is disclosed, never interpreted as readiness. */
internal class NativeReadinessJournal(
    private val maximumRows: Int = 128,
    private val maximumBytes: Int = 256 * 1024,
) {
    companion object {
        const val MAXIMUM_ROWS = 128
        const val MAXIMUM_BYTES = 256 * 1024
    }
    data class Capture(val seen: Long, val dropped: Long, val bytes: Int, val rows: List<String>)
    private val rows = ArrayDeque<Pair<String, Int>>()
    private var seen = 0L
    private var dropped = 0L
    private var bytes = 0
    init { require(maximumRows in 1..MAXIMUM_ROWS && maximumBytes in 1..MAXIMUM_BYTES) }

    @Synchronized fun append(encode: (Long) -> String) {
        seen++
        val row = encode(seen)
        val size = row.toByteArray(Charsets.UTF_8).size
        if (size > maximumBytes) { dropped++; return }
        while (rows.size >= maximumRows || bytes + size > maximumBytes) {
            bytes -= rows.removeFirst().second
            dropped++
        }
        rows.addLast(row to size)
        bytes += size
    }

    @Synchronized fun capture() = Capture(seen, dropped, bytes, rows.map { it.first })
}
