package org.wonad.desktop.broker

import org.junit.Assert.*
import org.junit.Test
import org.wonad.server.input.InputNative

/** Unprivileged JNI execution; the actual system_server hook needs a separate gate. */
class InputNativeTest {
    @Test fun commandPriorityIsTheExactRustAlphabetWithoutAnyInputAuthority() {
        val letters = setOf(31, 33, 34, 36, 38, 39, 40, 46, 48, 51, 62, 66)
        for (code in -1..400) assertEquals(code.toString(), code in 8..16 || code in letters,
            InputNative.commandKey(code))
        assertFalse(InputNative.commandKey(Int.MIN_VALUE))
        assertFalse(InputNative.commandKey(Int.MAX_VALUE))
        // Querying the alphabet alone cannot capture even a valid chord.
        val key = longArrayOf(100, 0, 7, 7, 1, 1, 1, 51, 0x11000, 0, 0, 1, 50, 0)
        assertEquals(0L, InputNative.event(key))
    }
    @Test fun uiOwnershipStaysBlankThroughDeathUntilFreshGenerationOrExactNativeDetach() {
        val display = 98
        val incarnation = 12345L
        assertFalse(InputNative.uiRenew(0, incarnation, 0, 10, 5000, 100, true))
        assertFalse(InputNative.uiRenew(display, incarnation, 0, 10, 5000, 100, false))
        assertTrue(InputNative.uiRenew(display, incarnation, 0, 10, 5000, 100, true))
        assertEquals(1, InputNative.uiMode(display, incarnation, 101, true, 0))
        InputNative.uiPark(display, incarnation, 9) // Old death callback cannot park the live owner.
        assertEquals(1, InputNative.uiMode(display, incarnation, 102, true, 0))
        InputNative.uiPark(display, incarnation, 10)
        assertEquals(2, InputNative.uiMode(display, incarnation, 103, true, 0))
        assertFalse(InputNative.uiRenew(display, incarnation, 0, 10, 5000, 104, true))
        assertTrue(InputNative.uiRenew(display, incarnation, 0, 11, 5000, 105, true))
        assertEquals(1, InputNative.uiMode(display, incarnation, 106, true, 0))
        assertEquals(2, InputNative.uiMode(display, incarnation, 107, true, 1))
        assertEquals(2, InputNative.uiMode(display, incarnation, 108, true, 0))
        InputNative.uiDetach(display, incarnation + 1)
        assertEquals(2, InputNative.uiMode(display, incarnation, 109, true, 0))
        InputNative.uiDetach(display, incarnation)
        assertEquals(0, InputNative.uiMode(display, incarnation, 110, true, 0))
        assertEquals(0, InputNative.uiMode(0, incarnation, 111, true, 0))
    }

    @Test fun privateInputBridgeEnforcesLeaseScopeAndDrainsOnlyClaimedKeys() {
        val down = longArrayOf(100, 0, 2, 2, 1, 1, 1, 38, 0x11000, 0, 0, 3, 50, 0)
        assertFalse(InputNative.renew(91, 0, 0, 5100, 100))
        assertFalse(InputNative.renew(91, 0, 2, 5101, 100))
        assertTrue(InputNative.renew(91, 0, 2, 5100, 100))
        assertEquals(0L, InputNative.event(LongArray(13)))
        assertEquals(0L, InputNative.event(LongArray(15)))
        assertEquals(0L, InputNative.event(down.copyOf().also { it[7] = Long.MAX_VALUE }))
        assertEquals(0L, InputNative.event(down.copyOf().also { it[4] = 256 }))
        assertEquals(0L, InputNative.event(down.copyOf().also { it[2] = 0; it[3] = 0 }))
        assertEquals(1L shl 32, InputNative.event(down))
        assertEquals(-1L, InputNative.event(down.copyOf().also { it[10] = 1 }))
        InputNative.release(91)
        val up = down.copyOf().also { it[2] = 0; it[3] = 0; it[8] = 0; it[9] = 1 }
        assertEquals(-1L, InputNative.event(up))
        assertEquals(0L, InputNative.event(up))
        assertEquals(0L, InputNative.event(down.copyOf().also { it[12] = 60 }))
        assertTrue(InputNative.renew(92, 0, 2, 5200, 200))
        InputNative.release(91) // Late death must not remove the newer lease.
        assertEquals(1L shl 32, InputNative.event(down.copyOf().also { it[0] = 201; it[12] = 60 }))
        assertEquals(0L, InputNative.event(down.copyOf().also { it[0] = 5200; it[12] = 61 }))
        InputNative.release(92)
    }
}
