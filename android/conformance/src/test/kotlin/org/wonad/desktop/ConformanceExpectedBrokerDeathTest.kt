package org.wonad.desktop

import android.os.IBinder
import java.lang.reflect.Proxy
import org.junit.Assert.*
import org.junit.Test

/** Real Android interface linkage with an explicit JVM transport double.
 * This does not execute Android Binder, SystemUI death or admission policy. */
class ConformanceExpectedBrokerDeathTest {
    private class Transport {
        var alive = true
        var recipient: IBinder.DeathRecipient? = null
        var links = 0
        var unlinks = 0
        val binder = Proxy.newProxyInstance(IBinder::class.java.classLoader, arrayOf(IBinder::class.java)) { _, method, args ->
            when (method.name) {
                "isBinderAlive" -> alive
                "linkToDeath" -> { recipient = args!![0] as IBinder.DeathRecipient; links++; null }
                "unlinkToDeath" -> { assertSame(recipient, args!![0]); unlinks++; true }
                else -> error("Unexpected local transport method ${method.name}")
            }
        } as IBinder
        fun die() { alive = false; checkNotNull(recipient).binderDied() }
    }
    private fun rejects(block: () -> Unit) {
        var rejected = false
        try { block() } catch (_: IllegalArgumentException) { rejected = true }
        catch (_: IllegalStateException) { rejected = true }
        assertTrue("Invalid planned death was admitted", rejected)
    }

    @Test fun exactTestControlHasNoInventedSdkRevocationReason() {
        val run = "a".repeat(32); val nonce = "b".repeat(32)
        val value = RuntimeHostInstruction.parse(arrayOf("runtime-command", run, nonce, "expect-broker-death", "41", "99"))
        assertEquals(41L to 99L, value.brokerDeath)
        assertNull(value.revocation)
        for (extra in listOf(arrayOf("0", "99"), arrayOf("41", "099"), arrayOf("41", "99", "5")))
            rejects { RuntimeHostInstruction.parse(arrayOf("runtime-command", run, nonce, "expect-broker-death", *extra)) }
    }

    @Test fun actualRegisteredRecipientAndExactOwnerAreRequired() {
        var now = 10L
        val value = ConformanceExpectedBrokerDeath { now }; val owner = Any(); val transport = Transport()
        value.register(owner, transport.binder, 41, 99)
        assertEquals(1, transport.links)
        assertFalse(value.consume(owner, 41, 99)) // A heartbeat error is not death.
        rejects { value.arm("a".repeat(32), Any(), 41, 99) }
        value.arm("a".repeat(32), owner, 41, 99)
        now = 20; transport.die()
        assertTrue(value.consume(owner, 41, 99))
        assertTrue(value.json().contains("\"state\":\"consumed\""))
        value.retire(); assertEquals(1, transport.unlinks)
    }

    @Test fun unplannedExpiredAndDuplicateActualCallbacksFail() {
        for (kind in 0..2) {
            var now = 10L
            val value = ConformanceExpectedBrokerDeath { now }; val owner = Any(); val transport = Transport()
            value.register(owner, transport.binder, 41, 99)
            if (kind != 0) value.arm("a".repeat(32), owner, 41, 99)
            if (kind == 1) now = 120_011
            transport.die()
            if (kind == 2) transport.die()
            rejects { value.consume(owner, 41, 99) }
            value.retire()
        }
    }

    @Test fun lateOriginalRecipientCannotAlterReplacementEvenWithReusedNumbers() {
        val value = ConformanceExpectedBrokerDeath { 10L }; val old = Any(); val original = Transport()
        value.register(old, original.binder, 41, 99); value.arm("a".repeat(32), old, 41, 99)
        original.die(); assertTrue(value.consume(old, 41, 99)); val late = original.recipient!!
        value.retire()
        val next = Any(); val replacement = Transport()
        value.register(next, replacement.binder, 41, 99)
        late.binderDied()
        assertFalse(value.consume(next, 41, 99))
        rejects { value.arm("a".repeat(32), next, 41, 99) }
        value.arm("b".repeat(32), next, 41, 99)
        replacement.die(); assertTrue(value.consume(next, 41, 99)); value.retire()
    }
}
