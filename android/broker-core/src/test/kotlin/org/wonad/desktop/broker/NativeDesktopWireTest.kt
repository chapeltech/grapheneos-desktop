package org.wonad.desktop.broker

import org.junit.Assert.*
import org.junit.Test
import org.wonad.desktop.api.*

/** Real Kotlin parcelable -> JNI -> Rust tests. These do not qualify native WM. */
class NativeDesktopWireTest {
    private fun bounds(left: Int = 0, top: Int = 0, right: Int = 1920, bottom: Int = 1080) =
        DesktopRect().apply { this.left = left; this.top = top; this.right = right; this.bottom = bottom }
    private fun snapshot() = DesktopSnapshot().apply {
        generation = 91; revision = 5; topologyRevision = 7; focusedDisplayToken = 101; focusedToken = 71
        displays = arrayOf(DesktopDisplay().apply {
            token = 101; displayId = 2; bounds = bounds(); densityDpi = 160; secure = true; shellGeneration = 91; identityHint = 401
        })
        tasks = arrayOf(DesktopTask().apply {
            token = 71; displayToken = 101; bounds = bounds(3, 3, 1003, 1003)
            minimumWidth = 320; minimumHeight = 200; resizable = true; visible = true; inputEnabled = true; zOrder = 0
            title = "not passed to Rust"; packageName = "org.example"
        })
    }
    private fun frame() = DesktopFrame().apply {
        topologyRevision = 7; focusedDisplayToken = 101; focusedToken = 71
        placements = arrayOf(DesktopPlacement().apply {
            token = 71; destinationDisplayToken = 101; bounds = bounds(3, 3, 1003, 1003)
            visible = true; inputEnabled = true; zOrder = 0
        })
        shellRegions = arrayOf(DesktopShellRegion().apply { generation = 91; displayToken = 101; bounds = bounds(0, 0, 1006, 3) })
    }
    @Test fun snapshotAndFrameHaveTheExactWorkspaceFreeScalarRows() {
        assertArrayEquals(longArrayOf(91, 5, 7, 1, 1, 101, 2, 0, 0, 1920, 1080, 160, 1, 91,
            71, 101, 3, 3, 1003, 1003, 320, 200, 1, 1, 1, 0), NativeDesktopWire.snapshot(snapshot()))
        assertArrayEquals(longArrayOf(91, 5, 7, 101, 71, 1, 1, 71, 101, 3, 3, 1003, 1003, 1, 1, 0,
            91, 101, 0, 0, 1006, 3), NativeDesktopWire.frame(91, 5, frame()))
        val empty = snapshot().apply { tasks = emptyArray() }
        assertEquals(14, NativeDesktopWire.snapshot(empty).size)
        val noRegions = frame().apply { shellRegions = emptyArray() }
        assertEquals(16, NativeDesktopWire.frame(91, 5, noRegions).size)
    }

    @Test fun capacityAndNullContainersAreRejectedBeforePacking() {
        assertThrows(IllegalArgumentException::class.java) { NativeDesktopWire.snapshot(snapshot().apply { displays = null }) }
        assertThrows(IllegalArgumentException::class.java) { NativeDesktopWire.snapshot(snapshot().apply { tasks = null }) }
        assertThrows(IllegalArgumentException::class.java) { NativeDesktopWire.snapshot(snapshot().apply {
            tasks = Array(129) { tasks[0] } }) }
        assertThrows(IllegalArgumentException::class.java) { NativeDesktopWire.snapshot(snapshot().apply {
            displays = Array(10) { displays[0] } }) }
        assertThrows(IllegalArgumentException::class.java) { NativeDesktopWire.frame(91, 5, frame().apply { placements = null }) }
        assertThrows(IllegalArgumentException::class.java) { NativeDesktopWire.frame(91, 5, frame().apply { shellRegions = null }) }
        assertThrows(IllegalArgumentException::class.java) { NativeDesktopWire.frame(91, 5, frame().apply {
            shellRegions = Array(769) { shellRegions[0] } }) }
    }

    @Test fun nativeTaskIdentityRowsRejectUidAndIncarnationRacesBeforeRegistryMutation() {
        val row = longArrayOf(3, 3, 1003, 1003, 320, 200, 1, 1, 1, 0, 101, 71, 10152)
        assertTrue(NativeDesktopWire.nativeTaskStateValid(row, intArrayOf(10152), setOf(101)))
        assertTrue(NativeDesktopWire.nativeTaskIdentityMatches(row, 71, 10152))
        assertFalse(NativeDesktopWire.nativeTaskIdentityMatches(row, 72, 10152))
        assertFalse(NativeDesktopWire.nativeTaskIdentityMatches(row, 71, 10153))
        // A live reparent can temporarily lack publishable geometry. Presence
        // still holds, without allowing an invalid or removed destination.
        val migrating = row.copyOf().also { it[2] = 0; it[10] = 102 }
        assertTrue(NativeDesktopWire.nativeTaskIdentityMatches(migrating, 71, 10152))
        assertFalse(NativeDesktopWire.nativeTaskStateValid(migrating, intArrayOf(10152), setOf(101)))
        assertTrue(NativeDesktopWire.nativeTaskStateValid(longArrayOf(), intArrayOf(), setOf(101)))
        assertFalse(NativeDesktopWire.nativeTaskStateValid(row, intArrayOf(10153), setOf(101)))
        assertFalse(NativeDesktopWire.nativeTaskStateValid(row, intArrayOf(10152), setOf(102)))
        assertFalse(NativeDesktopWire.nativeTaskStateValid(row.copyOf(11), intArrayOf(10152), setOf(101)))
        assertFalse(NativeDesktopWire.nativeTaskStateValid(row + row, intArrayOf(10152, 10152), setOf(101)))
        for ((index, value) in listOf(0 to -32769L, 2 to 0L, 4 to -1L, 6 to 2L, 9 to -1L, 11 to 0L, 12 to 1000L)) {
            assertFalse("native column $index", NativeDesktopWire.nativeTaskStateValid(row.copyOf().also { it[index] = value },
                intArrayOf(10152), setOf(101)))
        }
    }

    @Test fun finiteSignedNativeObservationsPreserveExactIdentityAndRejectOversizedGeometry() {
        val row = longArrayOf(-100, -50, 900, 950, 320, 200, 1, 1, 1, 0, 101, 71, 10152)
        assertTrue(NativeDesktopWire.nativeTaskStateValid(row, intArrayOf(10152), setOf(101)))
        for (rect in arrayOf(longArrayOf(2000, 2000, 3000, 3000),
                longArrayOf(-2000, -2000, -1000, -1000), longArrayOf(-32768, -32768, 0, 0),
                longArrayOf(0, 0, 32768, 32768))) {
            assertTrue(NativeDesktopWire.nativeTaskStateValid(row.copyOf().also { rect.copyInto(it) },
                intArrayOf(10152), setOf(101)))
        }
        for (rect in arrayOf(longArrayOf(Long.MIN_VALUE, 0, Long.MAX_VALUE, 10),
                longArrayOf(-32769, 0, 0, 100), longArrayOf(0, 0, 32769, 100),
                longArrayOf(-32768, 0, 32768, 100), longArrayOf(0, 10, 100, 10))) {
            assertFalse(NativeDesktopWire.nativeTaskStateValid(row.copyOf().also { rect.copyInto(it) },
                intArrayOf(10152), setOf(101)))
        }
        assertFalse(NativeDesktopWire.nativeTaskStateValid(row, intArrayOf(10153), setOf(101)))
        assertFalse(NativeDesktopWire.nativeTaskStateValid(row, intArrayOf(10152), setOf(102)))
    }

    @Test fun additiveSignedJniRpcKeepsOldDesiredContainmentAndNativeRegionOwnership() {
        for (rect in arrayOf(bounds(-100, -50, 900, 950), bounds(2000, 2000, 3000, 3000),
                bounds(-2000, -2000, -1000, -1000))) {
            val requested = frame().apply { placements.single().bounds = rect }
            val current = NativeDesktopWire.snapshot(snapshot())
            val desired = NativeDesktopWire.frame(91, 5, requested)
            assertEquals(DesktopProtocol.RESULT_APPLIED, BrokerNative.nativeValidateSignedFrame(current, desired))
            assertEquals(DesktopProtocol.RESULT_INVALID, BrokerNative.nativeValidateFrame(current, desired))
            val actual = NativeDesktopWire.snapshot(snapshot().apply { tasks.single().bounds = rect })
            assertTrue(BrokerNative.nativeFrameMatches(actual, desired))
            assertTrue(BrokerNative.nativeTaskAllowed(actual, 71, true))
            assertEquals(DesktopProtocol.RESULT_APPLIED,
                BrokerNative.nativeValidateFrame(actual, NativeDesktopWire.frame(91, 5, frame())))
            requested.shellRegions.single().bounds.left = -1
            assertEquals(DesktopProtocol.RESULT_INVALID,
                BrokerNative.nativeValidateSignedFrame(current, NativeDesktopWire.frame(91, 5, requested)))
        }
    }

    @Test fun snapshotCheckpointEpochAndModalGateDoNotBecomeNativeFramePolicy() {
        val observed = snapshot()
        val wire = NativeDesktopWire.snapshot(observed)
        observed.identityEpoch = 8123
        observed.interactionBlocked = true
        observed.displays.single().identityHint = 402
        assertArrayEquals(wire, NativeDesktopWire.snapshot(observed))
    }

    @Test fun realJniValidatesPixelsScopeVisibilityAndActualCompletionNotJustAck() {
        val current = NativeDesktopWire.snapshot(snapshot())
        val desired = NativeDesktopWire.frame(91, 5, frame())
        assertEquals(DesktopProtocol.RESULT_APPLIED, BrokerNative.nativeValidateFrame(current, desired))
        assertTrue(BrokerNative.nativeFrameMatches(current, desired))
        assertTrue(BrokerNative.nativeTaskAllowed(current, 71, true))
        assertFalse(BrokerNative.nativeTaskAllowed(current, 72, false))
        assertEquals(DesktopProtocol.RESULT_STALE, BrokerNative.nativeValidateFrame(current, desired.copyOf().also { it[1]-- }))
        assertEquals(DesktopProtocol.RESULT_INVALID, BrokerNative.nativeValidateFrame(current, desired.copyOf().also { it[17] = 102 }))
        assertEquals(DesktopProtocol.RESULT_INVALID, BrokerNative.nativeValidateFrame(current, desired.copyOf().also { it[16] = 90 }))
        assertEquals(DesktopProtocol.RESULT_INVALID, BrokerNative.nativeValidateFrame(current, desired.copyOf().also { it[19] = -1 }))
        assertEquals(DesktopProtocol.RESULT_INVALID, BrokerNative.nativeValidateFrame(current, desired.copyOf().also { it[14] = 0 }))
        assertEquals(DesktopProtocol.RESULT_PLATFORM_CONSTRAINT,
            BrokerNative.nativeValidateFrame(current, desired.copyOf().also { it[11] = 100 }))
        assertFalse(BrokerNative.nativeFrameMatches(current, desired.copyOf().also { it[9] = 4 }))
        assertEquals(DesktopProtocol.RESULT_INVALID, BrokerNative.nativeValidateFrame(LongArray(1700), desired))
        assertEquals(DesktopProtocol.RESULT_INVALID, BrokerNative.nativeValidateFrame(current, LongArray(6000)))
        repeat(1000) { assertEquals(DesktopProtocol.RESULT_APPLIED, BrokerNative.nativeValidateFrame(current, desired)) }
    }

    @Test fun neutralAuthorityAndPickerFacadeRejectStaleDisplayIncarnationsAndReplay() {
        NativeBrokerTestAuthority.ensureInitialized()
        val signer = 0xababababababababuL.toLong()
        var values = longArrayOf(100, 0, 0, 5, 5, 3, 10152, 0, 1, 0, signer, signer, signer, signer,
            0, 7, 1, 0, 1, 101, 2, 0, 0, 1920, 1080, 160, 1, 0)
        assertEquals(-100L, BrokerNative.nativeSession(1, LongArray(18)))
        assertEquals(-1L, BrokerNative.nativeSession(1, values.copyOf().also { it[8] = 0 }))
        assertEquals(-2L, BrokerNative.nativeSession(1, values.copyOf().also { it[5] = 2 }))
        val generation = BrokerNative.nativeSession(1, values)
        assertTrue(generation > 0)
        values[1] = generation; values[2] = 1
        assertEquals(0L, BrokerNative.nativeSession(4, values))
        val beforeReplug = values.copyOf()
        values = values.copyOf().also { it[15] = 8; it[19] = 102 }
        assertEquals(0L, BrokerNative.nativeSession(2, values))
        assertEquals(0L, BrokerNative.nativeSession(5, beforeReplug))
        assertEquals(1L, BrokerNative.nativeSession(4, beforeReplug.copyOf().also { it[2] = 2 }))
        values[2] = 2
        assertEquals(0L, BrokerNative.nativeSession(4, values))
        assertEquals(1L, BrokerNative.nativeSession(5, values))
        val ticket = BrokerNative.nativePicker(1, longArrayOf(100, 0, generation, 0, 102, 1, 3))
        assertTrue(ticket > 0)
        assertEquals(1L, BrokerNative.nativePicker(2, longArrayOf(101, ticket, generation, 0, 102, 1, 0)))
        assertEquals(1L, BrokerNative.nativePicker(3, longArrayOf(102, ticket, generation, 0, 102, 1, 2)))
        assertEquals(0L, BrokerNative.nativePicker(3, longArrayOf(103, ticket, generation, 0, 102, 1, 2)))
        assertEquals(1L, BrokerNative.nativeSession(7, values))
        assertEquals(4L, BrokerNative.nativeSession(4, values))
    }
}
