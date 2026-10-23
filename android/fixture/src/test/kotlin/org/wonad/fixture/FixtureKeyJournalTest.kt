package org.wonad.fixture

import org.junit.Assert.*
import org.junit.Test

class FixtureKeyJournalTest {
    private fun observed(journal: FixtureKeyJournal, recipient: String = "base", dialog: String? = null,
        action: Int = 0, key: Int = 113, meta: Int = 0, time: Long = 100) =
        journal.observe(recipient, dialog, action, key, meta, 0, -1, 257, 0, time, time)

    @Test fun recordsActualBaseAndDialogFieldsWithoutChangingThem() {
        val journal = FixtureKeyJournal()
        observed(journal)
        observed(journal, "dialog", "actual-dialog", action = 1, meta = 0x33000)
        val snapshot = journal.snapshot()
        assertEquals(2L, snapshot.total)
        assertEquals(listOf(1L, 2L), snapshot.entries.map { it.sequence })
        assertEquals(listOf("base", "dialog"), snapshot.entries.map { it.recipient })
        assertEquals(listOf(null, "actual-dialog"), snapshot.entries.map { it.dialogInstance })
        assertEquals(listOf(0, 0x33000), snapshot.entries.map { it.meta })
        assertTrue(snapshot.entries.all { it.device == -1 && it.source == 257 && it.downTime == 100L && it.eventTime == 100L })
    }

    @Test fun boundedHistoryPreservesSequenceAndImmutablePriorSnapshots() {
        val journal = FixtureKeyJournal()
        observed(journal)
        val original = journal.snapshot()
        repeat(511) { observed(journal, key = it, time = it.toLong()) }
        val current = journal.snapshot()
        assertEquals(512L, current.total)
        assertEquals(128, current.entries.size)
        assertEquals((385L..512L).toList(), current.entries.map { it.sequence })
        assertEquals(1L, original.total)
        assertEquals(1, original.entries.size)
        assertEquals(113, original.entries.single().key)
    }

    @Test fun cannotLabelARealBaseCallbackAsADialogOrInventAMissingRecipient() {
        for ((recipient, dialog) in listOf("base" to "foreign", "dialog" to null, "foreign" to null)) {
            val journal = FixtureKeyJournal()
            try { observed(journal, recipient, dialog); fail("Invalid callback recipient accepted") }
            catch (_: IllegalArgumentException) { }
            assertEquals(0L, journal.snapshot().total)
        }
    }
}
