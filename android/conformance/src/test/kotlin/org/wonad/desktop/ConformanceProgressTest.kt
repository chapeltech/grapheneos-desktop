package org.wonad.desktop

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.wonad.desktop.api.DesktopDisplay
import org.wonad.desktop.api.DesktopProtocol
import org.wonad.desktop.api.DesktopSnapshot
import org.wonad.desktop.api.DesktopTask

class ConformanceProgressTest {
    private fun state(revision: Long = 12, blocked: Boolean = false,
        focusedDisplay: Long = 101, focusedTask: Long = 201,
        displays: Set<Long> = setOf(101), tasks: Set<Long> = setOf(201, 202)) =
        ConformanceProgress.State(41, revision, blocked, focusedDisplay, focusedTask,
            displays, tasks)

    private fun command(generation: Long = 41, task: Long = 201, display: Long = 101) =
        ConformanceProgress.Command(generation, task, display)

    private fun result(generation: Long = 41, value: Int = DesktopProtocol.RESULT_APPLIED,
        revision: Long = 12) = ConformanceProgress.Result(generation, value, revision)

    private fun snapshot(revision: Long, focusedTask: Long) = DesktopSnapshot().also { value ->
        value.generation = 41
        value.revision = revision
        value.focusedDisplayToken = 101
        value.focusedToken = focusedTask
        value.displays = arrayOf(DesktopDisplay().also { it.token = 101 })
        value.tasks = arrayOf(
            DesktopTask().also { it.token = 201; it.displayToken = 101 },
            DesktopTask().also { it.token = 202; it.displayToken = 101 },
        )
    }

    private val status = object : ConformanceStatus {
        override fun json() = "{}"
        override fun terminalState() = "running"
        override fun callback(name: String) = Unit
        override fun facade(name: String, valid: Boolean) = Unit
    }

    @Test fun shortcutWaitRejectsThePreCommandFocusAndAcceptsTheBoundCommandState() {
        assertFalse(ConformanceProgress.afterCommand(
            state(revision = 11, focusedTask = 202), 41, command()))
        assertTrue(ConformanceProgress.afterCommand(state(), 41, command()))
    }

    @Test fun shortcutWaitBindsGenerationDisplayTaskReadinessAndBlocking() {
        assertFalse(ConformanceProgress.afterCommand(state(), 42, command()))
        assertFalse(ConformanceProgress.afterCommand(state(), 41, command(generation = 42)))
        assertFalse(ConformanceProgress.afterCommand(state(revision = 0), 41, command()))
        assertFalse(ConformanceProgress.afterCommand(state(blocked = true), 41, command()))
        assertFalse(ConformanceProgress.afterCommand(state(tasks = setOf(201)), 41, command()))
        assertFalse(ConformanceProgress.afterCommand(state(), 41, command(display = 102)))
        assertFalse(ConformanceProgress.afterCommand(state(), 41, command(task = 203)))
        assertFalse(ConformanceProgress.afterCommand(
            state(focusedDisplay = 102), 41, command()))
        assertFalse(ConformanceProgress.afterCommand(state(focusedTask = 202), 41, command()))
    }

    @Test fun appliedWaitRejectsPreResultRevisionAndAcceptsExactOrNewerObservation() {
        assertFalse(ConformanceProgress.afterApplied(state(revision = 11), 41,
            result(revision = 12), 2))
        assertTrue(ConformanceProgress.afterApplied(state(revision = 12), 41,
            result(revision = 12), 2))
        assertTrue(ConformanceProgress.afterApplied(state(revision = 13), 41,
            result(revision = 12), 2))
    }

    @Test fun appliedWaitBindsResultGenerationStatusReadinessAndBlocking() {
        assertFalse(ConformanceProgress.afterApplied(state(), 42, result(), 2))
        assertFalse(ConformanceProgress.afterApplied(state(), 41,
            result(generation = 42), 2))
        assertFalse(ConformanceProgress.afterApplied(state(), 41,
            result(value = DesktopProtocol.RESULT_STALE), 2))
        assertFalse(ConformanceProgress.afterApplied(state(), 41,
            result(revision = 0), 2))
        assertFalse(ConformanceProgress.afterApplied(state(blocked = true), 41, result(), 2))
        assertFalse(ConformanceProgress.afterApplied(
            state(displays = emptySet()), 41, result(), 2))
        assertFalse(ConformanceProgress.afterApplied(
            state(tasks = setOf(201)), 41, result(), 2))
        assertFalse(ConformanceProgress.afterApplied(state(), 41, result(), -1))
    }

    @Test fun realCallbackDtosAdvanceCommandAndResultRevisionFloors() {
        val events = ConformanceEvents(status)
        val before = snapshot(revision = 11, focusedTask = 202)
        val current = snapshot(revision = 12, focusedTask = 201)
        events.onSnapshot(before)
        events.onSnapshot(current)
        events.onCommand(41, DesktopProtocol.COMMAND_NEXT_LAYOUT, 0, 201, 101)

        val commandEvent = events.awaitCommand(10)
        val commandProgress = ConformanceProgress.Command(commandEvent.generation,
            commandEvent.taskToken, commandEvent.displayToken)
        assertFalse(ConformanceProgress.afterCommand(
            ConformanceProgress.observe(before), 41, commandProgress))
        val latest = checkNotNull(events.latestSnapshot())
        assertEquals(12L, latest.revision)
        assertTrue(ConformanceProgress.afterCommand(
            ConformanceProgress.observe(latest), 41, commandProgress))

        events.onResult(41, 0x3001, DesktopProtocol.RESULT_APPLIED, 13)
        val resultEvent = checkNotNull(events.pollResult(10))
        val resultProgress = ConformanceProgress.Result(resultEvent.generation,
            resultEvent.result, resultEvent.revision)
        assertFalse(ConformanceProgress.afterApplied(
            ConformanceProgress.observe(latest), 41, resultProgress, 2))
        events.onSnapshot(snapshot(revision = 13, focusedTask = 201))
        assertTrue(ConformanceProgress.afterApplied(
            ConformanceProgress.observe(checkNotNull(events.latestSnapshot())),
            41, resultProgress, 2))
    }
}
