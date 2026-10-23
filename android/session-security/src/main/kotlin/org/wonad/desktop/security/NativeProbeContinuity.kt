package org.wonad.desktop.security

/** Test-client identity assertions only. No task ID, geometry or workspace can
 * substitute for the OS-issued exact Task/UID identity namespace. */
internal data class NativeProbeContinuity(
    val generation: Long,
    val identityEpoch: Long,
    val taskTokens: Set<Long>,
) {
    init {
        require(generation > 0 && identityEpoch > 0)
        require(taskTokens.isNotEmpty() && taskTokens.size <= 128 && taskTokens.all { it > 0 })
    }

    fun requireRecovery(nextGeneration: Long, nextEpoch: Long, nextTokens: List<Long>) {
        check(nextGeneration > 0 && nextGeneration != generation) { "Revoked native generation was reused" }
        check(nextEpoch == identityEpoch) { "Native identity namespace changed during the probe" }
        check(nextTokens.size == nextTokens.toSet().size && nextTokens.toSet() == taskTokens) {
            "Native Task/UID identities were lost, replaced or duplicated"
        }
    }
}
