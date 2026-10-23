package org.wonad.desktop

import org.wonad.desktop.api.DesktopProtocol

/** Auditable test surface. These names are checked against the frozen AIDL. */
internal object ConformanceContract {
    const val ACTION_RUN = "org.wonad.desktop.conformance.RUN"
    const val EXTRA_MODE = "mode"
    const val EXTRA_RUN = "run"
    const val MODE_FULL = "full"
    const val MODE_RUNTIME = "runtime"
    const val EXTRA_NONCE = "nonce"
    const val EXTRA_PHASE = "phase"
    const val RUNTIME_COMMAND = "runtime-command"
    const val RUNTIME_START = "start"
    const val RUNTIME_CHECKPOINT = "checkpoint"
    const val RUNTIME_COPY_OBSERVED = "copy-observed"
    const val RUNTIME_MALFORMED_OBSERVED = "malformed-observed"
    const val RUNTIME_REMEMBER_OBSERVED = "remember-observed"
    const val RUNTIME_RESTORE_OBSERVED = "restore-observed"
    const val RUNTIME_REOPEN = "reopen"
    const val RUNTIME_EXPECT_REVOCATION = "expect-revocation"
    const val RUNTIME_EXPECT_BROKER_DEATH = "expect-broker-death"
    const val RUNTIME_STOP = "stop"
    const val MAX_RUNTIME_HANDSHAKES = 4096
    const val BIND_ACTION = "org.wonad.desktop.BIND"
    const val BROKER_PACKAGE = "com.android.systemui"
    const val BROKER_CLASS = "org.wonad.desktop.broker.WonadBrokerService"
    const val SHELL_GENERATION = "org.wonad.desktop.shell.GENERATION"
    const val SHELL_DISPLAY_TOKEN = "org.wonad.desktop.shell.DISPLAY_TOKEN"
    const val LAUNCHER_CATALOG = "catalog"
    const val LAUNCHER_GENERATION = "generation"

    val brokerOperations = listOf("getApiVersion", "getCapabilities", "openSession")
    val sessionOperations = listOf("applyFrame", "focusTask", "closeTask", "enableShortcuts",
        "heartbeat", "release", "enableExternalUi", "showShell", "launcherPage", "showLauncher",
        "selectLauncher", "showTransferPicker", "applySignedFrame")
    val callbacks = listOf("onSnapshot", "onCommand", "onResult", "onRevoked")
    val capabilities = linkedMapOf(
        "CAP_SHORTCUTS" to DesktopProtocol.CAP_SHORTCUTS,
        "CAP_TRANSFER_PICKER" to DesktopProtocol.CAP_TRANSFER_PICKER,
        "CAP_EXTERNAL_UI" to DesktopProtocol.CAP_EXTERNAL_UI,
        "CAP_APK_LAUNCHER" to DesktopProtocol.CAP_APK_LAUNCHER,
        "CAP_FRAME" to DesktopProtocol.CAP_FRAME,
        "CAP_SHELL" to DesktopProtocol.CAP_SHELL,
        "CAP_SIGNED_PLACEMENT" to DesktopProtocol.CAP_SIGNED_PLACEMENT,
    )
    val requiredCapabilities = capabilities.values.fold(0L) { value, bit -> value or bit }
    val allOperations = brokerOperations + sessionOperations
    val runtimePhases = setOf(RUNTIME_CHECKPOINT, RUNTIME_COPY_OBSERVED,
        RUNTIME_REMEMBER_OBSERVED, RUNTIME_RESTORE_OBSERVED, RUNTIME_REOPEN, RUNTIME_STOP, RUNTIME_EXPECT_REVOCATION,
        RUNTIME_EXPECT_BROKER_DEATH, RUNTIME_MALFORMED_OBSERVED)
    // TEST-client callback expectations, not new OS reasons or permissions.
    // CLIENT_FAILED is needed after a deliberately frozen heartbeat owner.
    val expectedRevocationReasons = setOf(DesktopProtocol.REVOKED_LOCKED,
        DesktopProtocol.REVOKED_USER_CHANGED, DesktopProtocol.REVOKED_CLIENT_FAILED)
    val runtimeCapabilities = DesktopProtocol.CAP_EXTERNAL_UI or DesktopProtocol.CAP_SHELL or
        DesktopProtocol.CAP_FRAME

    fun validRun(value: String): Boolean = value.matches(Regex("[0-9a-f]{32}"))
    fun validNonce(value: String): Boolean = value.matches(Regex("[0-9a-f]{32}"))
    fun validMode(value: String): Boolean = value == MODE_FULL || value == MODE_RUNTIME
}
