package org.wonad.desktop.transitionfault

/** Test-only exact-payload matcher, independent of Android for JVM regression.
 * It never changes/validates production authority or substitutes numeric task
 * IDs for the native objects. Mutable request arrays are defensively copied. */
internal class NativeCompletionScope private constructor(
    val user: Int,
    val generation: Long,
    private val owner: Any,
    private val binders: List<Any>,
    private val uids: IntArray,
    private val capturedCurrent: LongArray,
    private val capturedDesired: LongArray,
) {
    val current: LongArray get() = capturedCurrent.copyOf()
    val desired: LongArray get() = capturedDesired.copyOf()
    fun matches(user: Int, generation: Long, owner: Any?, binders: List<Any>, uids: IntArray,
        current: LongArray, desired: LongArray): Boolean = this.user == user && this.generation == generation &&
        this.owner === owner && this.binders.size == binders.size && this.binders.indices.all { this.binders[it] === binders[it] } &&
        this.uids.contentEquals(uids) && capturedCurrent.contentEquals(current) && capturedDesired.contentEquals(desired)

    companion object {
        fun capture(user: Int, generation: Long, owner: Any, binders: List<Any>, uids: IntArray,
            current: LongArray, desired: LongArray, fixtureUid: Int, displayTokens: Set<Long>, taskTokens: Set<Long>): NativeCompletionScope? {
            if (user != 0 || generation <= 0 || fixtureUid !in 10000..19999 || displayTokens.size !in 1..9 ||
                displayTokens.any { it <= 0 } || taskTokens.size != 2 || taskTokens.any { it <= 0 } ||
                binders.size != 2 || binders[0] === binders[1] || uids.size != 2 || uids.any { it != fixtureUid } ||
                current.size < 5 || desired.size < 7 || current[0] != generation || desired[0] != generation ||
                current[1] <= 0 || current[2] <= 0 || desired[1] != current[1] || desired[2] != current[2] ||
                current[3] != displayTokens.size.toLong() || current[4] != 2L || desired[5] != 2L || desired[6] != 0L ||
                desired[3] != 0L || desired[4] != 0L || current.size != 5 + displayTokens.size * 9 + 2 * 12 ||
                desired.size != 7 + 2 * 9) return null
            val taskStart = 5 + displayTokens.size * 9
            val nativeDisplays = (displayTokens.indices).map { index -> current[5 + index * 9] }
            if (nativeDisplays.toSet() != displayTokens || nativeDisplays.distinct().size != nativeDisplays.size ||
                displayTokens.indices.any { index -> current[5 + index * 9 + 1] <= 0 ||
                    current[5 + index * 9 + 7] != 1L || current[5 + index * 9 + 8] != generation }) return null
            val nativeTasks = (0..1).map { index -> current[taskStart + index * 12] }
            val placements = (0..1).map { index -> desired[7 + index * 9] }
            if (nativeTasks.toSet() != taskTokens || placements.toSet() != taskTokens || nativeTasks.distinct().size != 2 ||
                placements.distinct().size != 2 || (0..1).any { index ->
                    current[taskStart + index * 12 + 1] !in displayTokens || desired[7 + index * 9 + 1] !in displayTokens ||
                    current[taskStart + index * 12 + 9] != 1L || current[taskStart + index * 12 + 10] != 1L ||
                    desired[7 + index * 9 + 6] != 1L || desired[7 + index * 9 + 7] != 1L
                }) return null
            val changed = (0..1).any { index ->
                val placementAt = 7 + index * 9
                val nativeAt = taskStart + nativeTasks.indexOf(desired[placementAt]) * 12
                (2..5).any { field -> desired[placementAt + field] != current[nativeAt + field] }
            }
            if (!changed) return null
            return NativeCompletionScope(user, generation, owner, binders.toList(), uids.copyOf(), current.copyOf(), desired.copyOf())
        }
    }
}
