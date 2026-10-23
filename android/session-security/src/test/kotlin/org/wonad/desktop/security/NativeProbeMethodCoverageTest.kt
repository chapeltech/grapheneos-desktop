package org.wonad.desktop.security

import org.junit.Assert.assertEquals
import org.junit.Test
import org.wonad.desktop.api.DesktopProtocol
import org.wonad.desktop.api.IDesktopSession

/** Compiled generated-AIDL coverage, not a real Binder/security receipt. */
class NativeProbeMethodCoverageTest {
    private val expected = listOf("applyFrame", "focusTask", "closeTask", "enableShortcuts", "heartbeat", "release",
        "enableExternalUi", "showShell", "launcherPage", "showLauncher", "selectLauncher", "showTransferPicker",
        "applySignedFrame")

    @Test fun retainedAndForeignListsCoverEveryAppendOnlyTransactionExactlyOnce() {
        assertEquals(expected, NativeSecurityClient.METHODS)
        assertEquals(expected, NativeAttackService.METHODS)
        val transactions = IDesktopSession.Stub::class.java.declaredFields
            .filter { it.name.startsWith("TRANSACTION_") }
            .associate { it.name.removePrefix("TRANSACTION_") to it.also { field -> field.isAccessible = true }.getInt(null) }
        assertEquals(expected.toSet(), transactions.keys)
        assertEquals((1..13).toList(), expected.map { transactions.getValue(it) })
    }

    @Test fun signedExtensionKeepsApiAndOldDeadlineUnchanged() {
        assertEquals(3, DesktopProtocol.API_VERSION)
        assertEquals(1024L, DesktopProtocol.CAP_SIGNED_PLACEMENT)
        assertEquals(15000L, DesktopProtocol.TRANSACTION_TIMEOUT_MILLIS)
    }
}
