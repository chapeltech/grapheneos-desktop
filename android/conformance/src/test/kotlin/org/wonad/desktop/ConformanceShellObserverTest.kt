package org.wonad.desktop

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ConformanceShellObserverTest {
    @Test fun delayedParentCreatesExactlyOneObserver() {
        val lifecycle = ConformanceShellObserverLifecycle()
        assertEquals(ConformanceShellObserverLifecycle.Action.RETRY,
            lifecycle.next(claimValid = true, parentReady = false))
        assertEquals(ConformanceShellObserverLifecycle.Action.INSTALL,
            lifecycle.next(claimValid = true, parentReady = true))
        lifecycle.installed()
        assertEquals(ConformanceShellObserverLifecycle.Action.STOP,
            lifecycle.next(claimValid = true, parentReady = true))
        assertTrue(lifecycle.terminate())
        assertFalse(lifecycle.terminate())
    }

    @Test fun revocationOrDestroyMakesDelayedCallbacksTerminal() {
        val revoked = ConformanceShellObserverLifecycle()
        assertEquals(ConformanceShellObserverLifecycle.Action.RETRY,
            revoked.next(claimValid = true, parentReady = false))
        assertEquals(ConformanceShellObserverLifecycle.Action.STOP,
            revoked.next(claimValid = false, parentReady = true))
        assertEquals(ConformanceShellObserverLifecycle.Action.STOP,
            revoked.next(claimValid = true, parentReady = true))
        assertFalse(revoked.terminate())

        val destroyed = ConformanceShellObserverLifecycle()
        assertFalse(destroyed.terminate())
        assertEquals(ConformanceShellObserverLifecycle.Action.STOP,
            destroyed.next(claimValid = true, parentReady = true))
    }
}
