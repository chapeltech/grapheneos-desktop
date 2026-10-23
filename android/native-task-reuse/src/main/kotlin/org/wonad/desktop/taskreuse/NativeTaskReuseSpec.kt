package org.wonad.desktop.taskreuse

/** Test-only assertions about real public API results, never an allocator. */
internal class NativeTaskReuseSpec(val original: Int) {
    init { require(original in 1..99999) }
    var allocations = 0; private set
    var wraps = 0; private set
    private var previous = original
    fun observed(id: Int): Boolean {
        require(id in 0..99999 && allocations < 100000)
        allocations++
        if (id < previous) wraps++
        previous = id
        if (id != original) return false
        check(allocations in 99000..100000 && wraps == 1) { "Not one full real task-ID allocator cycle" }
        return true
    }
    companion object {
        const val SCOPE = "native_v3_task_reuse"
        const val PACKAGE = "org.wonad.desktop.taskreuse"
        const val COMPONENT = "$PACKAGE/.RecyclerActivity"
        const val NEXT = "$PACKAGE.NEXT"
        val STALE = listOf("focusTask", "closeTask", "applyFrame", "applySignedFrame")
    }
}
