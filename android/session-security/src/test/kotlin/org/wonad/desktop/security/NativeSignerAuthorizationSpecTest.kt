package org.wonad.desktop.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class NativeSignerAuthorizationSpecTest {
    private val run = "a".repeat(32)
    private val trusted = "b".repeat(64)
    private val wrong = "c".repeat(64)

    @Test fun nativeApiAndAllThreeActualBrokerMethods() {
        assertEquals(3, NativeSignerAuthorizationSpec.API)
        assertEquals(listOf("getApiVersion", "getCapabilities", "openSession"),
            NativeSignerAuthorizationSpec.METHODS)
        assertEquals("native_v3_wrong_signer", NativeSignerAuthorizationSpec.SCOPE)
        assertEquals("Wonad signer not allowed", NativeSignerAuthorizationSpec.DENIAL)
    }

    @Test fun exactOrdinaryOwnerAndDifferentCertificateRequired() {
        for (uid in listOf(10000, 10180, 19999)) {
            NativeSignerAuthorizationSpec.requireArguments(run, uid, trusted, wrong)
        }
        for (uid in listOf(-1, 0, 1000, 9999, 20000, 110180)) {
            assertThrows(IllegalStateException::class.java) {
                NativeSignerAuthorizationSpec.requireArguments(run, uid, trusted, wrong)
            }
        }
        assertThrows(IllegalStateException::class.java) {
            NativeSignerAuthorizationSpec.requireArguments(run, 10180, trusted, trusted)
        }
    }

    @Test fun noMalformedOrAmbiguousRunOrCertificate() {
        for (value in listOf("", "a".repeat(31), "a".repeat(33), "A".repeat(32), run + "\n")) {
            assertThrows(IllegalStateException::class.java) {
                NativeSignerAuthorizationSpec.requireArguments(value, 10180, trusted, wrong)
            }
        }
        for (value in listOf("", "c".repeat(63), "c".repeat(65), "C".repeat(64), wrong + "\n")) {
            assertThrows(IllegalStateException::class.java) {
                NativeSignerAuthorizationSpec.requireArguments(run, 10180, trusted, value)
            }
            assertThrows(IllegalStateException::class.java) {
                NativeSignerAuthorizationSpec.requireArguments(run, 10180, value, wrong)
            }
        }
    }
}
