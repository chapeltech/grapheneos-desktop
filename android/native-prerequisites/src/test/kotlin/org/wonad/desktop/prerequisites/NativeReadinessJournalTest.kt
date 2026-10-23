package org.wonad.desktop.prerequisites

import org.junit.Assert.*
import org.junit.Test

class NativeReadinessJournalTest {
    @Test fun retainedActualSequenceAndUtf8ByteBudget() {
        val journal = NativeReadinessJournal(maximumRows = 3, maximumBytes = 9)
        repeat(4) { journal.append { sequence -> "$sequence:é" } }
        val capture = journal.capture()
        assertEquals(4L, capture.seen); assertEquals(2L, capture.dropped)
        assertEquals(listOf("3:é", "4:é"), capture.rows); assertEquals(8, capture.bytes)
    }
    @Test fun callbackLimitDisclosesEvictionAndKeepsLatest() {
        val journal = NativeReadinessJournal(maximumRows = 2, maximumBytes = 100)
        repeat(4) { journal.append { sequence -> sequence.toString() } }
        assertEquals(listOf("3", "4"), journal.capture().rows)
        assertEquals(2L, journal.capture().dropped)
    }
    @Test fun oversizeNeverReplacesActualObservedRowsOrInventsState() {
        val journal = NativeReadinessJournal(maximumRows = 3, maximumBytes = 8)
        journal.append { "first" }; journal.append { "too-large" }; journal.append { "last" }
        assertEquals(listOf("last"), journal.capture().rows)
        assertEquals(3L, journal.capture().seen); assertEquals(2L, journal.capture().dropped)
    }
    @Test fun capturedJournalCannotMutateLiveCallbackEvidence() {
        val journal = NativeReadinessJournal()
        journal.append { "original" }; val original = journal.capture()
        journal.append { "next" }
        assertEquals(listOf("original"), original.rows)
        assertEquals(listOf("original", "next"), journal.capture().rows)
    }
}
