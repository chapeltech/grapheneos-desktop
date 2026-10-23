package org.wonad.desktop.broker

import org.junit.Assert.assertTrue

/** Native generations cannot be reset between JVM tests. Initialize all three
 * independent protocol test authorities once, regardless of JUnit class order.
 */
internal object NativeBrokerTestAuthority {
    private var initialized = false
    @Synchronized fun ensureInitialized() {
        if (!initialized) {
            assertTrue(BrokerNative.initialize(ByteArray(32) { 0xab.toByte() }, 1000))
            initialized = true
        }
    }
}
