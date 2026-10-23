package org.wonad.desktop

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConformanceStartupTest {
    private fun state(tasks: Int, shell: Long = 0, blocked: Boolean = false) =
        ConformanceStartup.State(41,
            listOf(ConformanceStartup.Display(101, 3, shell)), tasks, blocked)

    @Test fun zeroTaskInitialSnapshotStartsLeaseBeforeWaitingForTasks() {
        val initial = state(tasks = 0)
        assertTrue(ConformanceStartup.initialReady(initial))
        assertTrue(ConformanceStartup.initialReady(state(tasks = 0, blocked = true)))
        assertFalse(ConformanceStartup.externallyReady(initial, 41))

        val calls = mutableListOf<String>()
        ConformanceStartup.activate(initial,
            register = { generation, displays ->
                assertEquals(41L, generation)
                assertEquals(listOf(101L to 3), displays)
                calls += "register"
            },
            startHeartbeat = { calls += "heartbeat" },
            enableExternalUi = { calls += "enable-ui" },
            showShell = { token -> calls += "show-shell:$token" })

        assertEquals(listOf("register", "heartbeat", "enable-ui", "show-shell:101"), calls)
        assertFalse(ConformanceStartup.externallyReady(state(tasks = 2), 41))
        assertFalse(ConformanceStartup.externallyReady(state(tasks = 1, shell = 41), 41))
        assertFalse(ConformanceStartup.externallyReady(state(tasks = 2, shell = 41, blocked = true), 41))
        assertTrue(ConformanceStartup.externallyReady(state(tasks = 2, shell = 41), 41))
    }

    @Test fun activationFailurePropagatesBeforeLaterCallsForRunnerCleanup() {
        val calls = mutableListOf<String>()
        val failure = IllegalStateException("heartbeat startup failed")
        try {
            ConformanceStartup.activate(state(tasks = 0),
                register = { _, _ -> calls += "register" },
                startHeartbeat = { calls += "heartbeat"; throw failure },
                enableExternalUi = { calls += "enable-ui" },
                showShell = { calls += "show-shell" })
            error("startup failure was swallowed")
        } catch (actual: IllegalStateException) {
            assertTrue(actual === failure)
        }
        assertEquals(listOf("register", "heartbeat"), calls)
    }

    @Test fun invalidInitialSnapshotCannotStartAnyLeaseAction() {
        val invalid = listOf(
            state(tasks = 0).copy(generation = 0),
            state(tasks = 0).copy(displays = emptyList()),
        )
        invalid.forEach { value ->
            val calls = mutableListOf<String>()
            try {
                ConformanceStartup.activate(value,
                    register = { _, _ -> calls += "register" },
                    startHeartbeat = { calls += "heartbeat" },
                    enableExternalUi = { calls += "enable-ui" },
                    showShell = { calls += "show-shell" })
                error("invalid initial snapshot was accepted")
            } catch (_: IllegalStateException) { }
            assertEquals(emptyList<String>(), calls)
        }
    }
}
