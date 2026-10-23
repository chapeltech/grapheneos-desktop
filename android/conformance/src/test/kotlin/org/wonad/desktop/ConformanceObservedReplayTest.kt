package org.wonad.desktop

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/** Real worker DTOs and replay implementation; no broker or driver behavior is mocked as proof. */
class ConformanceObservedReplayTest {
    private fun saved() = RuntimeSnapshot(
        41, 7, 3, 99, 101, 201, false,
        listOf(
            RuntimeDisplay(101, 3, 301, 41, 160, RuntimeRect(0, 0, 4000, 2000)),
            RuntimeDisplay(102, 4, 302, 41, 240, RuntimeRect(0, 0, 1920, 1080)),
            RuntimeDisplay(103, 5, 303, 41, 320, RuntimeRect(0, 0, 2560, 1440)),
        ),
        listOf(
            RuntimeTask(201, 101, 10, 20, true, true, true, 0, "Red", "org.wonad.fixture", RuntimeRect(0, 0, 4000, 2000)),
            RuntimeTask(202, 102, 30, 40, false, true, true, 1, "Green", "org.wonad.fixture", RuntimeRect(20, 30, 1720, 1030)),
            RuntimeTask(203, 103, 0, 0, true, false, false, 2, "Blue", "org.wonad.fixture", RuntimeRect(0, 0, 2560, 1440)),
        ),
    )

    private fun redocked(value: RuntimeSnapshot = saved()) = value.copy(
        revision = 11, topologyRevision = 5,
        displays = value.displays.map { if (it.token == 101L) it.copy(token = 104, displayId = 6) else it },
        tasks = value.tasks.map { if (it.displayToken == 101L) it.copy(displayToken = 102, visible = false, inputEnabled = false) else it },
    )

    private fun rejected(saved: RuntimeSnapshot, current: RuntimeSnapshot) {
        var rejected = false
        try { ConformanceObservedReplay.placements(saved, current) }
        catch (_: IllegalStateException) { rejected = true }
        assertTrue("invalid observation must fail closed", rejected)
    }

    private fun renewed(value: RuntimeSnapshot = saved()) = value.copy(
        generation = 9, revision = 1, topologyRevision = 1, identityEpoch = 2,
        displays = value.displays.map { it.copy(token = it.token + 100, displayId = it.displayId + 10, shellGeneration = 9) },
        tasks = value.tasks.reversed().map { it.copy(token = it.token + 100, displayToken = 201,
            visible = false, inputEnabled = false, bounds = RuntimeRect(0, 0, 10, 10)) },
    )

    private fun recoveryRejected(saved: RuntimeSnapshot, current: RuntimeSnapshot) {
        var rejected = false
        try { ConformanceObservedReplay.afterExpectedRevocation(saved, current) }
        catch (_: IllegalStateException) { rejected = true }
        assertTrue("invalid planned observation must fail closed", rejected)
    }

    @Test fun remapsOnlyTheReturnedConnectorIncarnationAndCopiesEveryObservedField() {
        val previous = saved()
        val result = ConformanceObservedReplay.placements(previous, redocked(previous))
        assertEquals(previous.tasks.map { if (it.displayToken == 101L) it.copy(displayToken = 104) else it }, result)
        result.zip(previous.tasks).forEach { (actual, original) -> assertSame(original.bounds, actual.bounds) }
        assertEquals(listOf(104L, 102L, 103L), result.map { it.displayToken })
    }

    @Test fun rejectsCrossLeaseAuthority() {
        val value = saved(); val current = redocked(value)
        rejected(value, current.copy(generation = 42))
        rejected(value, current.copy(identityEpoch = 100))
    }

    @Test fun rejectsRevisionAndTopologyRegression() {
        val value = saved(); val current = redocked(value)
        rejected(value, current.copy(revision = 6))
        rejected(value, current.copy(topologyRevision = 3))
        rejected(value, current.copy(topologyRevision = 2))
    }

    @Test fun rejectsBlockedOrUnreadySnapshots() {
        val value = saved(); val current = redocked(value)
        rejected(value.copy(interactionBlocked = true), current)
        rejected(value, current.copy(interactionBlocked = true))
        rejected(value.copy(displays = value.displays.map { it.copy(shellGeneration = 0) }), current)
        rejected(value, current.copy(displays = current.displays.map { it.copy(shellGeneration = 0) }))
    }

    @Test fun rejectsAmbiguousMissingOrDifferentConnectors() {
        val value = saved(); val current = redocked(value)
        rejected(value, current.copy(displays = current.displays.dropLast(1)))
        rejected(value, current.copy(displays = current.displays.map { it.copy(identityHint = 301) }))
        rejected(value.copy(displays = value.displays.map { it.copy(identityHint = 301) }), current)
        rejected(value, current.copy(displays = current.displays.map { it.copy(identityHint = it.identityHint + 10) }))
    }

    @Test fun rejectsGeometryAndDensityChangesRatherThanScaling() {
        val value = saved(); val current = redocked(value)
        rejected(value, current.copy(displays = current.displays.map { it.copy(densityDpi = it.densityDpi + 1) }))
        rejected(value, current.copy(displays = current.displays.map { it.copy(bounds = it.bounds.copy(right = it.bounds.right - 1)) }))
    }

    @Test fun rejectsMissingReplacedExtraOrEmptyTasks() {
        val value = saved(); val current = redocked(value)
        rejected(value, current.copy(tasks = current.tasks.dropLast(1)))
        rejected(value, current.copy(tasks = current.tasks.map { it.copy(token = it.token + 10) }))
        rejected(value, current.copy(tasks = current.tasks + current.tasks.first().copy(token = 204)))
        rejected(value.copy(tasks = emptyList()), current.copy(tasks = emptyList()))
    }

    @Test fun rejectsChangedObservedTaskConstraints() {
        val value = saved(); val current = redocked(value)
        rejected(value, current.copy(tasks = current.tasks.map { it.copy(packageName = "other.package") }))
        rejected(value, current.copy(tasks = current.tasks.map { it.copy(title = "Other") }))
        rejected(value, current.copy(tasks = current.tasks.map { it.copy(minimumWidth = it.minimumWidth + 1) }))
        rejected(value, current.copy(tasks = current.tasks.map { it.copy(minimumHeight = it.minimumHeight + 1) }))
        rejected(value, current.copy(tasks = current.tasks.map { it.copy(resizable = !it.resizable) }))
    }

    @Test fun plannedRecoveryUsesOnlyFreshTokensAndCopiesExactDescriptiveLayoutData() {
        val previous = saved(); val current = renewed(previous)
        val result = ConformanceObservedReplay.afterExpectedRevocation(previous, current)
        assertEquals(previous.tasks.map { it.copy(token = it.token + 100, displayToken = it.displayToken + 100) }, result)
        assertTrue(result.none { it.token in previous.tasks.map { old -> old.token } })
        assertTrue(result.none { it.displayToken in previous.displays.map { old -> old.token } })
        result.zip(previous.tasks).forEach { (actual, original) -> assertSame(original.bounds, actual.bounds) }
        // A generation/identity epoch is not a client-inferred counter.
        assertEquals(9L, current.generation)
        assertEquals(2L, current.identityEpoch)
        rejected(previous, current)
    }

    @Test fun plannedRecoveryRejectsInvalidLeaseOrMissingReadyPlanes() {
        val value = saved(); val current = renewed(value)
        recoveryRejected(value, current.copy(generation = value.generation))
        recoveryRejected(value, current.copy(generation = 0))
        recoveryRejected(value.copy(generation = 0), current)
        recoveryRejected(value, current.copy(identityEpoch = 0))
        recoveryRejected(value.copy(identityEpoch = 0), current)
        recoveryRejected(value, current.copy(revision = 0))
        recoveryRejected(value, current.copy(topologyRevision = 0))
        recoveryRejected(value.copy(interactionBlocked = true), current)
        recoveryRejected(value, current.copy(interactionBlocked = true))
        recoveryRejected(value, current.copy(displays = current.displays.map { it.copy(shellGeneration = value.generation) }))
    }

    @Test fun plannedRecoveryRejectsMissingChangedAndAmbiguousTaskDescriptions() {
        val value = saved(); val current = renewed(value)
        recoveryRejected(value, current.copy(tasks = current.tasks.dropLast(1)))
        recoveryRejected(value, current.copy(tasks = current.tasks + current.tasks.first().copy(token = 800)))
        recoveryRejected(value.copy(tasks = emptyList()), current.copy(tasks = emptyList()))
        recoveryRejected(value, current.copy(tasks = current.tasks.map { it.copy(packageName = "other.package") }))
        recoveryRejected(value, current.copy(tasks = current.tasks.map { it.copy(title = "Other") }))
        recoveryRejected(value, current.copy(tasks = current.tasks.map { it.copy(minimumWidth = it.minimumWidth + 1) }))
        recoveryRejected(value, current.copy(tasks = current.tasks.map { it.copy(minimumHeight = it.minimumHeight + 1) }))
        recoveryRejected(value, current.copy(tasks = current.tasks.map { it.copy(resizable = !it.resizable) }))
        recoveryRejected(value, current.copy(tasks = current.tasks.map { it.copy(token = 800) }))
        val duplicated = value.tasks.first().copy(token = 800)
        recoveryRejected(value.copy(tasks = value.tasks + duplicated), current)
    }

    @Test fun plannedRecoveryRejectsChangedConnectorSetGeometryAndDensity() {
        val value = saved(); val current = renewed(value)
        recoveryRejected(value, current.copy(displays = current.displays.dropLast(1)))
        recoveryRejected(value, current.copy(displays = current.displays.map { it.copy(identityHint = 301) }))
        recoveryRejected(value.copy(displays = value.displays.map { it.copy(identityHint = 301) }), current)
        recoveryRejected(value, current.copy(displays = current.displays.map { it.copy(identityHint = it.identityHint + 10) }))
        recoveryRejected(value, current.copy(displays = current.displays.map { it.copy(densityDpi = it.densityDpi + 1) }))
        recoveryRejected(value, current.copy(displays = current.displays.map { it.copy(bounds = it.bounds.copy(right = it.bounds.right - 1)) }))
    }

    @Test fun newHostPhasesAreAcceptedAsBoundedExplicitInstructions() {
        val run = "0123456789abcdef0123456789abcdef"
        val nonce = "33333333333333333333333333333333"
        for (phase in listOf(ConformanceContract.RUNTIME_REMEMBER_OBSERVED, ConformanceContract.RUNTIME_RESTORE_OBSERVED)) {
            assertEquals(phase, RuntimeHostInstruction.parse(arrayOf("runtime-command", run, nonce, phase)).phase)
        }
        assertEquals(4096, ConformanceContract.MAX_RUNTIME_HANDSHAKES)
    }
}
