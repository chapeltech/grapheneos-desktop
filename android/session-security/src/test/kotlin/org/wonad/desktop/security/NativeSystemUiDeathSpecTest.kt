package org.wonad.desktop.security

import org.junit.Assert.*
import org.junit.Test

class NativeSystemUiDeathSpecTest {
    private fun calls() = NativeSystemUiDeathSpec.sessionMethods.mapIndexed { index, method ->
        NativeSystemUiDeathSpec.DeadCall("session", method, index + 1, "android.os.DeadObjectException") } +
        NativeSystemUiDeathSpec.brokerMethods.zip(listOf(1, 2, 4)).map { (method, transaction) ->
            NativeSystemUiDeathSpec.DeadCall("broker", method, transaction, "android.os.DeadObjectException") }
    private fun rejected(block: () -> Unit) { try { block(); fail("Accepted false native death proof") } catch (_: IllegalArgumentException) {} }
    @Test fun allCurrentSignedThirteenAndBrokerThreeAreRequired() {
        NativeSystemUiDeathSpec.requireCalls(calls())
        assertEquals("applySignedFrame", calls()[12].method)
        rejected { NativeSystemUiDeathSpec.requireCalls(calls().filter { it.transaction != 13 }) }
        rejected { NativeSystemUiDeathSpec.requireCalls(calls().dropLast(1)) }
        rejected { NativeSystemUiDeathSpec.requireCalls(calls() + calls()[0]) }
    }
    @Test fun noGenericExceptionOrWrongTransactionCanStandInForDeath() {
        rejected { NativeSystemUiDeathSpec.requireCalls(calls().map { it.copy(exception = "android.os.RemoteException") }) }
        rejected { NativeSystemUiDeathSpec.requireCalls(calls().map { it.copy(transaction = 1) }) }
    }
    @Test fun oldCallbacksCannotReviveWhenNewLeaseDraws() {
        NativeSystemUiDeathSpec.requireSilent(listOf(5, 0, 0, 0), listOf(5, 0, 0, 0))
        rejected { NativeSystemUiDeathSpec.requireSilent(listOf(5, 0, 0, 0), listOf(6, 0, 0, 0)) }
        rejected { NativeSystemUiDeathSpec.requireSilent(listOf(5, 0, 0, 0), listOf(5, 0, 1, 0)) }
        rejected { NativeSystemUiDeathSpec.requireSilent(listOf(-1, 0, 0, 0), listOf(-1, 0, 0, 0)) }
    }
    @Test fun onlyARealFreshGenerationCanRecover() {
        NativeSystemUiDeathSpec.requireFresh(1, 2)
        rejected { NativeSystemUiDeathSpec.requireFresh(1, 1) }
        rejected { NativeSystemUiDeathSpec.requireFresh(0, 2) }
    }
}
