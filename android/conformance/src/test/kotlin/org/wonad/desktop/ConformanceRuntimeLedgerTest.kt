package org.wonad.desktop

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConformanceRuntimeLedgerTest {
    private val run = "0123456789abcdef0123456789abcdef"
    private val start = "11111111111111111111111111111111"
    private fun snapshot(shell: Long = 41) = RuntimeSnapshot(
        generation = 41, revision = 7, topologyRevision = 3, identityEpoch = 99,
        focusedDisplayToken = 101, focusedToken = 201, interactionBlocked = false,
        displays = listOf(RuntimeDisplay(101, 3, 301, shell, 160,
            RuntimeRect(0, 0, 1920, 1080))),
        tasks = listOf(RuntimeTask(201, 101, 0, 0, true, true, true, 0,
            "Fixture", "org.wonad.fixture", RuntimeRect(0, 0, 1920, 1080))),
    )

    @Test fun readinessIsSeparateFromOneShotCoverageAndPublishesBoundedIdentity() {
        var now = 10L
        val ledger = ConformanceRuntimeLedger(run, start) { now++ }
        ledger.negotiated(3, ConformanceContract.runtimeCapabilities)
        ledger.snapshot(snapshot())
        ledger.ready(start, ConformanceContract.RUNTIME_START)
        val json = ledger.json()
        assertTrue(ledger.initialReady(start))
        assertTrue(json.contains("\"one_shot_api_coverage\":{\"mode\":\"full\",\"status\":\"not_run\"}"))
        assertTrue(json.contains("\"identity_epoch\":99"))
        assertTrue(json.contains("\"display_incarnations\":[{\"token\":101"))
        assertTrue(json.contains("\"tasks\":[{\"token\":201"))
    }

    @Test fun finalUndockRequiresFreshExplicitReopenHandshake() {
        val ledger = ConformanceRuntimeLedger(run, start) { 10 }
        ledger.negotiated(3, ConformanceContract.runtimeCapabilities)
        ledger.snapshot(snapshot())
        ledger.ready(start, ConformanceContract.RUNTIME_START)
        ledger.undocked(2)
        assertTrue(ledger.json().contains("\"reopen_required\":true"))
        val reopen = "22222222222222222222222222222222"
        ledger.request(reopen, ConformanceContract.RUNTIME_REOPEN)
        ledger.negotiated(3, ConformanceContract.runtimeCapabilities)
        ledger.snapshot(snapshot())
        ledger.ready(reopen, ConformanceContract.RUNTIME_REOPEN)
        assertTrue(ledger.json().contains("\"reopen_required\":false"))
    }

    @Test fun nonceReplayAndUnreadyShellFailClosed() {
        val ledger = ConformanceRuntimeLedger(run, start) { 10 }
        ledger.negotiated(3, ConformanceContract.runtimeCapabilities)
        ledger.snapshot(snapshot(shell = 0))
        try { ledger.ready(start, ConformanceContract.RUNTIME_START); error("unready shell accepted") }
        catch (_: IllegalStateException) { }
        assertFalse(ledger.initialReady(start))
        ledger.syncingShells()
        ledger.snapshot(snapshot())
        ledger.ready(start, ConformanceContract.RUNTIME_START)
        try { ledger.request(start, ConformanceContract.RUNTIME_CHECKPOINT); error("nonce replay accepted") }
        catch (_: IllegalStateException) { }
    }

    @Test fun hostCommandParserHasOneExactBoundedShape() {
        val value = RuntimeHostInstruction.parse(arrayOf("runtime-command", run,
            "33333333333333333333333333333333", "copy-observed"))
        assertTrue(value.phase == ConformanceContract.RUNTIME_COPY_OBSERVED)
        for (bad in listOf(
            arrayOf("runtime-command", run, "short", "copy-observed"),
            arrayOf("runtime-command", run, start, "layout"),
            arrayOf("runtime-command", run, start, "copy-observed", "extra"))) {
            try { RuntimeHostInstruction.parse(bad); error("bad command accepted") }
            catch (_: IllegalArgumentException) { }
        }
    }
}
