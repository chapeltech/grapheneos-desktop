package org.wonad.fixture

import org.junit.Assert.*
import org.junit.Test

class PaletteProbeLedgerTest {
    @Test fun actualSizeChangesAreIndependentOfFocusAndInput() {
        val ledger = PaletteProbeLedger()
        assertEquals(0, ledger.snapshot().width)
        ledger.configured(1018, 762); ledger.configured(1018, 762)
        assertEquals(1L, ledger.snapshot().configurations)
        ledger.focused(true); ledger.keyDown(30); ledger.pointerDown(8194, true); ledger.drawn()
        assertEquals(1018, ledger.snapshot().width)
        assertEquals(762, ledger.snapshot().height)
        assertEquals(1L, ledger.snapshot().keyDowns)
        assertEquals(1L, ledger.snapshot().mouseDowns)
        assertEquals(30, ledger.snapshot().lastKey)
        assertEquals(8194, ledger.snapshot().lastPointerSource)
        assertTrue(ledger.snapshot().focused)
        assertEquals(1L, ledger.snapshot().draws)
        ledger.configured(518, 294)
        assertEquals(2L, ledger.snapshot().configurations)
        assertEquals(1L, ledger.snapshot().mouseDowns)
    }
    @Test fun touchCannotStandInForMouseDelivery() {
        val ledger = PaletteProbeLedger()
        ledger.pointerDown(4098, false)
        assertEquals(1L, ledger.snapshot().pointerDowns)
        assertEquals(0L, ledger.snapshot().mouseDowns)
        ledger.pointerDown(8194, true)
        assertEquals(2L, ledger.snapshot().pointerDowns)
        assertEquals(1L, ledger.snapshot().mouseDowns)
    }
    @Test fun instancesRemainStableAcrossObservedResizesButDistinctAcrossActivities() {
        val ledger = PaletteProbeLedger(); val instance = ledger.instance
        ledger.configured(1018, 762); ledger.focused(true); ledger.configured(578, 354)
        assertEquals(instance, ledger.snapshot().instance)
        assertNotEquals(instance, PaletteProbeLedger().instance)
        ledger.focused(false); assertFalse(ledger.snapshot().focused)
    }
    @Test fun unboundedOrInvalidRealObservationsAreRejected() {
        val ledger = PaletteProbeLedger()
        for ((w, h) in listOf(0 to 30, 30 to 0, -1 to 10, 32769 to 1)) {
            try { ledger.configured(w, h); fail("Accepted $w,$h") } catch (_: IllegalArgumentException) {}
        }
        assertEquals(0L, ledger.snapshot().configurations)
        try { ledger.keyDown(-1); fail("Accepted invalid key") } catch (_: IllegalArgumentException) {}
        try { ledger.pointerDown(-1, true); fail("Accepted invalid source") } catch (_: IllegalArgumentException) {}
    }
}
