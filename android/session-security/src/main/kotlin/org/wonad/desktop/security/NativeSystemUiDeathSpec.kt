package org.wonad.desktop.security

/** Pure test-only assertions; actual Binder calls are made by instrumentation. */
internal object NativeSystemUiDeathSpec {
    val sessionMethods = listOf("applyFrame", "focusTask", "closeTask", "enableShortcuts", "heartbeat", "release",
        "enableExternalUi", "showShell", "launcherPage", "showLauncher", "selectLauncher", "showTransferPicker",
        "applySignedFrame")
    val brokerMethods = listOf("getApiVersion", "getCapabilities", "openSession")
    data class DeadCall(val role: String, val method: String, val transaction: Int, val exception: String)
    fun requireCalls(calls: List<DeadCall>) {
        val expected = sessionMethods.mapIndexed { index, method -> Triple("session", method, index + 1) } +
            brokerMethods.zip(listOf(1, 2, 4)).map { (method, transaction) -> Triple("broker", method, transaction) }
        require(calls.map { Triple(it.role, it.method, it.transaction) } == expected)
        require(calls.all { it.exception == "android.os.DeadObjectException" })
    }
    fun requireSilent(before: List<Long>, after: List<Long>) {
        require(before.size == 4 && before.all { it >= 0 } && before == after)
    }
    fun requireFresh(before: Long, after: Long) { require(before > 0 && after > 0 && before != after) }
}
