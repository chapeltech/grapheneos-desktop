package org.wonad.desktop

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.wonad.desktop.api.DesktopProtocol

class ConformanceContractTest {
    private fun moduleFile(path: String): File {
        val working = File(requireNotNull(System.getProperty("user.dir")))
        return listOf(File(working, path), File(working, "conformance/$path"),
            File(working.parentFile ?: working, "conformance/$path")).first { it.isFile }
    }

    @Test fun frozenCoverageListsEveryMethodCallbackAndCapability() {
        assertEquals(listOf("getApiVersion", "getCapabilities", "openSession"),
            ConformanceContract.brokerOperations)
        assertEquals(listOf("applyFrame", "focusTask", "closeTask", "enableShortcuts", "heartbeat", "release",
            "enableExternalUi", "showShell", "launcherPage", "showLauncher", "selectLauncher",
            "showTransferPicker", "applySignedFrame"), ConformanceContract.sessionOperations)
        assertEquals(listOf("onSnapshot", "onCommand", "onResult", "onRevoked"), ConformanceContract.callbacks)
        assertEquals(7, ConformanceContract.capabilities.size)
        assertEquals(DesktopProtocol.CAP_SHORTCUTS or DesktopProtocol.CAP_TRANSFER_PICKER or
            DesktopProtocol.CAP_EXTERNAL_UI or DesktopProtocol.CAP_APK_LAUNCHER or DesktopProtocol.CAP_FRAME or
            DesktopProtocol.CAP_SHELL or DesktopProtocol.CAP_SIGNED_PLACEMENT,
            ConformanceContract.requiredCapabilities)
    }

    @Test fun manifestHasExactGuardedFacadesAndNoRequestedPermission() {
        val document = DocumentBuilderFactory.newInstance().apply { isNamespaceAware = true }
            .newDocumentBuilder().parse(moduleFile("src/main/AndroidManifest.xml"))
        val android = "http://schemas.android.com/apk/res/android"
        assertEquals(0, document.getElementsByTagName("uses-permission").length)
        val activities = document.getElementsByTagName("activity")
        val expected = setOf(".ExternalHomeActivity", ".ExternalShellActivity", ".LauncherActivity")
        val guarded = (0 until activities.length).map { activities.item(it) }.filter {
            it.attributes.getNamedItemNS(android, "name")?.nodeValue in expected
        }
        assertEquals(3, guarded.size)
        guarded.forEach {
            assertEquals("true", it.attributes.getNamedItemNS(android, "exported").nodeValue)
            assertEquals("android.permission.STATUS_BAR_SERVICE",
                it.attributes.getNamedItemNS(android, "permission").nodeValue)
        }
        val service = document.getElementsByTagName("service").item(0)
        assertEquals("false", service.attributes.getNamedItemNS(android, "exported").nodeValue)
    }

    @Test fun fixedExtrasAndIdentityAreNotConfigurable() {
        assertEquals("org.wonad.desktop.shell.GENERATION", ConformanceContract.SHELL_GENERATION)
        assertEquals("org.wonad.desktop.shell.DISPLAY_TOKEN", ConformanceContract.SHELL_DISPLAY_TOKEN)
        assertEquals("catalog", ConformanceContract.LAUNCHER_CATALOG)
        assertEquals("generation", ConformanceContract.LAUNCHER_GENERATION)
        assertEquals("org.wonad.desktop.BIND", ConformanceContract.BIND_ACTION)
        assertEquals("com.android.systemui", ConformanceContract.BROKER_PACKAGE)
        assertTrue(ConformanceContract.validRun("0123456789abcdef0123456789abcdef"))
        assertFalse(ConformanceContract.validRun("0123456789ABCDEF0123456789ABCDEF"))
        assertTrue(ConformanceContract.validMode("full"))
        assertTrue(ConformanceContract.validMode("runtime"))
        assertFalse(ConformanceContract.validMode("layout"))
        assertTrue(ConformanceContract.validNonce("fedcba9876543210fedcba9876543210"))
        assertEquals("phase", ConformanceContract.EXTRA_PHASE)
        assertEquals(setOf("checkpoint", "copy-observed", "remember-observed", "restore-observed", "reopen", "stop", "expect-revocation", "expect-broker-death", "malformed-observed"),
            ConformanceContract.runtimePhases)
        assertEquals(DesktopProtocol.CAP_EXTERNAL_UI or DesktopProtocol.CAP_SHELL or
            DesktopProtocol.CAP_FRAME, ConformanceContract.runtimeCapabilities)
    }
}
