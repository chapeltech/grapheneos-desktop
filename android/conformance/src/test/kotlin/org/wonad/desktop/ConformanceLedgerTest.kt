package org.wonad.desktop

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ConformanceLedgerTest {
    private fun complete(ledger: ConformanceLedger) {
        ConformanceContract.allOperations.forEach(ledger::operation)
        ConformanceContract.callbacks.forEach(ledger::callback)
        ledger.negotiated(3, ConformanceContract.requiredCapabilities)
        for (name in listOf("ExternalHomeActivity", "ExternalShellActivity", "LauncherActivity"))
            ledger.facade(name, true)
    }

    @Test fun passRequiresAndReportsTheWholeFrozenSurface() {
        var now = 100L
        val ledger = ConformanceLedger("0123456789abcdef0123456789abcdef", "full") { now++ }
        complete(ledger)
        ledger.generation(41, listOf(7, 3, 7))
        ledger.pass()
        val json = ledger.json()
        assertTrue(json.contains("\"state\":\"passed\""))
        assertTrue(json.contains("\"phase\":\"complete\""))
        assertTrue(json.contains("\"display_ids\":[3,7]"))
        ConformanceContract.allOperations.forEach { assertEquals(1, Regex("\\\"$it\\\"").findAll(json).count()) }
    }

    @Test fun missingCallbackCannotPass() {
        val ledger = ConformanceLedger("0123456789abcdef0123456789abcdef", "full") { 10 }
        ConformanceContract.allOperations.forEach(ledger::operation)
        ConformanceContract.callbacks.dropLast(1).forEach(ledger::callback)
        ledger.negotiated(3, ConformanceContract.requiredCapabilities)
        for (name in listOf("ExternalHomeActivity", "ExternalShellActivity", "LauncherActivity"))
            ledger.facade(name, true)
        try { ledger.pass(); error("pass accepted incomplete callbacks") }
        catch (expected: IllegalStateException) { assertTrue(expected.message!!.contains("callbacks missing")) }
    }

    @Test fun failureTextIsBoundedAndJsonEscaped() {
        val ledger = ConformanceLedger("0123456789abcdef0123456789abcdef", "full") { 10 }
        ledger.fail(IllegalArgumentException("bad\n\"" + "x".repeat(2000)))
        val json = ledger.json()
        assertTrue(json.contains("\"state\":\"failed\""))
        assertTrue(json.contains("bad\\n\\\""))
        assertTrue(json.length < 1600)
    }
}
