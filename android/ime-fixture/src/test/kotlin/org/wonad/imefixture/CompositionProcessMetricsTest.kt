package org.wonad.imefixture

import org.junit.Assert.*
import org.junit.Test

class CompositionProcessMetricsTest {
    @Test fun displayRebindSharesTotalsButRecordsTwoGenuineServiceInstances() {
        val metrics = CompositionProcessMetrics()
        val first = metrics.create()
        metrics.start(first, false); metrics.start(first, true)
        metrics.keyDown(first); metrics.action(first, 137, true); metrics.keyUp(first)
        val old = metrics.snapshot(first)
        metrics.destroy(first)
        val second = metrics.create(); metrics.start(second, false)
        val new = metrics.snapshot(second)
        assertEquals(old.epoch, new.epoch)
        assertNotEquals(old.instance, new.instance)
        assertEquals(2, new.creates); assertEquals(1, new.destroys)
        assertEquals(2, new.sequence); assertTrue(new.alive)
        assertEquals(3, new.starts); assertEquals(1, new.restarts)
        assertEquals(1, new.actions); assertEquals("137:true", new.lastAction)
        assertEquals(1, new.keyDowns); assertEquals(1, new.keyUps)
        assertEquals(1, new.localStarts); assertEquals(0, new.localRestarts)
        assertEquals(0, new.localActions); assertEquals(0, new.localKeyDowns)
        assertEquals(0, new.localKeyUps)
    }

    @Test fun duplicateDeliveriesAreCountedWithoutInventingDuplicateConnectionAttempts() {
        val metrics = CompositionProcessMetrics(); val service = metrics.create()
        metrics.keyDown(service); metrics.action(service, 137, true)
        // CompositionIme's unchanged Press guard consumes this duplicate
        // without another actual InputConnection call.
        metrics.keyDown(service); metrics.keyUp(service); metrics.keyUp(service)
        val snapshot = metrics.snapshot(service)
        assertEquals(2, snapshot.keyDowns); assertEquals(2, snapshot.keyUps)
        assertEquals(1, snapshot.actions); assertEquals(1, snapshot.localActions)
    }

    @Test fun failedCompositionAttemptCannotBeErasedByDestroyingItsInstance() {
        val metrics = CompositionProcessMetrics(); val first = metrics.create()
        metrics.keyDown(first); metrics.action(first, 140, false); metrics.keyUp(first)
        metrics.destroy(first); val second = metrics.create()
        assertEquals(1, metrics.snapshot(second).actions)
        assertEquals("140:false", metrics.snapshot(second).lastAction)
        metrics.keyDown(second); metrics.action(second, 137, true); metrics.keyUp(second)
        assertEquals(2, metrics.snapshot(second).actions)
        assertEquals(1, metrics.snapshot(second).localActions)
    }

    @Test fun hiddenExtraActionSurvivesArbitrarilyManyRebindings() {
        val metrics = CompositionProcessMetrics(); var instance = metrics.create()
        metrics.keyDown(instance); metrics.action(instance, 139, true); metrics.keyUp(instance)
        repeat(5) {
            metrics.destroy(instance); instance = metrics.create()
            metrics.start(instance, false)
        }
        val snapshot = metrics.snapshot(instance)
        assertEquals(1, snapshot.actions); assertEquals(0, snapshot.localActions)
        assertEquals("139:true", snapshot.lastAction)
        assertEquals(6, snapshot.creates); assertEquals(5, snapshot.destroys)
    }

    @Test fun independentProcessHasNewEpochAndForeignInstanceCannotChangeItsTotals() {
        val first = CompositionProcessMetrics(); val second = CompositionProcessMetrics()
        assertNotEquals(first.epoch, second.epoch)
        val foreign = first.create(); val local = second.create()
        for (operation in listOf<() -> Unit>(
            { second.start(foreign, false) }, { second.action(foreign, 137, true) },
            { second.keyDown(foreign) }, { second.keyUp(foreign) }, { second.destroy(foreign) },
            { second.snapshot(foreign) }
        )) {
            try { operation(); fail("Foreign process instance admitted") }
            catch (_: IllegalStateException) { }
        }
        assertEquals(0, second.snapshot(local).actions)
    }

    @Test fun destructionIsRecordedOnceAndNoResetApiExists() {
        val metrics = CompositionProcessMetrics(); val instance = metrics.create()
        metrics.destroy(instance)
        assertFalse(metrics.snapshot(instance).alive)
        try { metrics.destroy(instance); fail("Duplicate destruction counted") }
        catch (_: IllegalStateException) { }
        assertEquals(1, metrics.snapshot(instance).destroys)
        assertFalse(CompositionProcessMetrics::class.java.declaredMethods.any {
            it.name.contains("reset", ignoreCase = true) || it.name.contains("clear", ignoreCase = true)
        })
    }
}
