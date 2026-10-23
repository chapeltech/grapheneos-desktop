package org.wonad.fixture

import org.junit.Assert.*
import org.junit.Test

class PublicKeyboardCaptureRequestTest {
    class Params {
        private var enabled = false
        fun setKeyboardCaptureEnabled(value: Boolean) { enabled = value }
        fun hasKeyboardCapture(): Boolean = enabled
    }
    class Missing
    class ThrowingParams {
        fun setKeyboardCaptureEnabled(value: Boolean) { throw IllegalStateException("not retained $value") }
        fun hasKeyboardCapture(): Boolean = false
    }
    @Test fun publicRequestOnAndOffAreExplicit() {
        val params = Params(); val api = PublicKeyboardCaptureRequest(Params::class.java)
        for (enabled in listOf(true, false)) {
            val result = api.request(params, enabled, true, {}, { params })
            assertEquals(PublicKeyboardCaptureRequest.Status.ATTRIBUTES_APPLIED, result.status)
            assertEquals(enabled, result.attributeEnabled); assertNull(result.errorClass)
        }
    }
    @Test fun unavailableApiNeverUpdatesWindow() {
        val params = Missing(); var updates = 0
        val result = PublicKeyboardCaptureRequest(Missing::class.java)
            .request(params, true, true, { updates++ }, { params })
        assertEquals(PublicKeyboardCaptureRequest.Status.API_UNAVAILABLE, result.status)
        assertEquals(0, updates); assertNull(result.attributeEnabled)
    }
    @Test fun missingNormalPermissionNeverRequestsOn() {
        val params = Params(); var updates = 0
        val result = PublicKeyboardCaptureRequest(Params::class.java)
            .request(params, true, false, { updates++ }, { params })
        assertEquals(PublicKeyboardCaptureRequest.Status.NORMAL_PERMISSION_MISSING, result.status)
        assertFalse(params.hasKeyboardCapture()); assertEquals(0, updates)
    }
    @Test fun disableIsPermittedWithoutNormalPermission() {
        val params = Params(); params.setKeyboardCaptureEnabled(true)
        val result = PublicKeyboardCaptureRequest(Params::class.java)
            .request(params, false, false, {}, { params })
        assertEquals(PublicKeyboardCaptureRequest.Status.ATTRIBUTES_APPLIED, result.status)
        assertEquals(false, result.attributeEnabled)
    }
    @Test fun setterErrorDoesNotRecordExceptionMessage() {
        val params = ThrowingParams()
        val result = PublicKeyboardCaptureRequest(ThrowingParams::class.java)
            .request(params, true, true, {}, { params })
        assertEquals(PublicKeyboardCaptureRequest.Status.PUBLIC_API_ERROR, result.status)
        assertEquals("java.lang.IllegalStateException", result.errorClass)
        assertNull(result.attributeEnabled)
    }
    @Test fun windowUpdateErrorDoesNotClaimAppliedCapture() {
        val params = Params()
        val result = PublicKeyboardCaptureRequest(Params::class.java)
            .request(params, true, true, { throw IllegalStateException("not retained") }, { params })
        assertEquals(PublicKeyboardCaptureRequest.Status.WINDOW_UPDATE_ERROR, result.status)
        assertNull(result.attributeEnabled)
    }
    @Test fun staleWindowAttributesAreExplicitMismatch() {
        val params = Params(); val stale = Params()
        val result = PublicKeyboardCaptureRequest(Params::class.java)
            .request(params, true, true, {}, { stale })
        assertEquals(PublicKeyboardCaptureRequest.Status.ATTRIBUTE_MISMATCH, result.status)
        assertEquals(false, result.attributeEnabled)
    }
}
