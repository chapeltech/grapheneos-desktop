package org.wonad.desktop.api

import org.junit.Assert.*
import org.junit.Test

class DesktopProtocolTest {
    @Test fun abiConstantsRemainStable() {
        assertEquals(3, DesktopProtocol.API_VERSION)
        assertEquals(128, DesktopProtocol.MAX_TASKS)
        assertEquals(9, DesktopProtocol.MAX_DISPLAYS)
        assertEquals(5000L, DesktopProtocol.CLIENT_TIMEOUT_MILLIS)
        assertEquals(15000L, DesktopProtocol.TRANSACTION_TIMEOUT_MILLIS)
        assertEquals(1L shl 3, DesktopProtocol.CAP_SHORTCUTS)
        assertEquals(1L shl 5, DesktopProtocol.CAP_TRANSFER_PICKER)
        assertEquals(1L shl 6, DesktopProtocol.CAP_EXTERNAL_UI)
        assertEquals(1L shl 7, DesktopProtocol.CAP_APK_LAUNCHER)
        assertEquals(1L shl 8, DesktopProtocol.CAP_FRAME)
        assertEquals(1L shl 9, DesktopProtocol.CAP_SHELL)
        assertEquals(1L shl 10, DesktopProtocol.CAP_SIGNED_PLACEMENT)
        val published = DesktopProtocol.CAP_SHORTCUTS or DesktopProtocol.CAP_TRANSFER_PICKER or
            DesktopProtocol.CAP_EXTERNAL_UI or DesktopProtocol.CAP_APK_LAUNCHER or
            DesktopProtocol.CAP_FRAME or DesktopProtocol.CAP_SHELL or
            DesktopProtocol.CAP_SIGNED_PLACEMENT
        assertEquals(0L, published and ((1L shl 0) or (1L shl 1) or (1L shl 2) or (1L shl 4)))
        assertEquals(0, DesktopProtocol.RESULT_APPLIED)
        assertEquals(6, DesktopProtocol.RESULT_PLATFORM_CONSTRAINT)
        assertEquals(15, DesktopProtocol.COMMAND_FOCUS_MONITOR)
        assertEquals(16, DesktopProtocol.COMMAND_SEND_TO_MONITOR)
    }

    @Test fun noAuthorityIsEmbeddedInTheSnapshot() {
        val state = DesktopSnapshot()
        assertEquals(0L, state.generation)
        assertEquals(0L, state.capabilities)
        assertNull(state.tasks)
        assertNull(state.displays)
        assertEquals(0L, state.topologyRevision)
    }

    @Test fun v3HasNoDefaultAuthorityOrWorkspacePolicy() {
        assertEquals(9, DesktopProtocol.MAX_DISPLAYS)
        assertEquals(768, DesktopProtocol.MAX_SHELL_REGIONS)
        assertEquals(".ExternalShellActivity", DesktopProtocol.SHELL_ACTIVITY)
        val snapshot = DesktopSnapshot()
        assertEquals(0L, snapshot.generation)
        assertEquals(0L, snapshot.capabilities)
        assertNull(snapshot.tasks)
        assertNull(snapshot.displays)
        assertEquals(0L, snapshot.focusedDisplayToken)
        val frame = DesktopFrame()
        assertNull(frame.placements)
        assertNull(frame.shellRegions)
        assertEquals(0L, frame.focusedToken)
        assertEquals(0L, DesktopDisplay().shellGeneration)
    }
}
