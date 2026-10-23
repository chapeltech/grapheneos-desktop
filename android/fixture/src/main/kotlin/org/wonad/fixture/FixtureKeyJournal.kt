package org.wonad.fixture

/** Bounded observations from real callbacks only; never dispatches or consumes input. */
class FixtureKeyJournal {
    data class Entry(val sequence: Long, val recipient: String, val dialogInstance: String?,
        val action: Int, val key: Int, val meta: Int, val repeat: Int, val device: Int,
        val source: Int, val flags: Int, val downTime: Long, val eventTime: Long)
    data class Snapshot(val total: Long, val entries: List<Entry>)
    private var total = 0L
    private val entries = ArrayDeque<Entry>()

    @Synchronized fun observe(recipient: String, dialogInstance: String?, action: Int, key: Int,
        meta: Int, repeat: Int, device: Int, source: Int, flags: Int, downTime: Long, eventTime: Long) {
        require(recipient == "base" && dialogInstance == null || recipient == "dialog" && dialogInstance != null)
        total = Math.addExact(total, 1L)
        entries.addLast(Entry(total, recipient, dialogInstance, action, key, meta, repeat,
            device, source, flags, downTime, eventTime))
        if (entries.size > CAPACITY) entries.removeFirst()
    }

    @Synchronized fun snapshot() = Snapshot(total, entries.toList())

    companion object { const val CAPACITY = 128 }
}
