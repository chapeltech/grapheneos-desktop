package org.wonad.fixture

import org.junit.Assert.*
import org.junit.Test

class PermissionRequestLedgerTest {
    private val camera = PermissionRequestLedger.Kind.CAMERA
    private val location = PermissionRequestLedger.Kind.LOCATION

    @Test fun nothingIsRequestedOrGrantedByConstructingTheFixture() {
        val state = PermissionRequestLedger().snapshot()
        assertEquals(0, state.requests)
        assertEquals(0, state.callbacks)
        assertNull(state.pending)
        assertNull(state.lastRequest)
        assertTrue(state.history.isEmpty())
    }

    @Test fun dangerousPermissionArraysAndRealRequestCodesAreDistinct() {
        assertEquals(6101, camera.code)
        assertEquals(6102, location.code)
        assertEquals(listOf("android.permission.CAMERA"), camera.permissions)
        assertEquals(listOf("android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION"), location.permissions)
    }

    @Test fun onePendingRequestCannotBeOverwrittenByRepeatedButtonOrKeyInput() {
        val ledger = PermissionRequestLedger()
        val request = ledger.begin(camera, "keyboard")!!
        assertNull(ledger.begin(location, "button"))
        assertNull(ledger.begin(camera, "keyboard"))
        assertEquals(request, ledger.snapshot().pending)
        assertEquals(1, ledger.snapshot().requests)
    }

    @Test fun allowReportsOnlyThePlatformSuppliedResultsAndKeepsOriginalRequestSerial() {
        val ledger = PermissionRequestLedger()
        val request = ledger.begin(camera, "button")!!
        ledger.callback(request.code, arrayOf("android.permission.CAMERA"), intArrayOf(0))
        val state = ledger.snapshot()
        val event = state.history.single()
        assertNull(state.pending)
        assertEquals(1, state.callbacks)
        assertEquals(request.serial, event.requestSerial)
        assertEquals(listOf(0), event.results)
        assertTrue(event.matchedRequest)
        assertTrue(event.permissionsMatch)
        assertFalse(event.cancelled)
    }

    @Test fun approximateAndDeniedLocationResultsRemainExactNotNormalizedToSuccess() {
        val ledger = PermissionRequestLedger()
        val request = ledger.begin(location, "keyboard")!!
        ledger.callback(request.code, request.permissions.toTypedArray(), intArrayOf(-1, 0))
        assertEquals(listOf(-1, 0), ledger.snapshot().history.single().results)
        assertTrue(ledger.snapshot().history.single().permissionsMatch)
        ledger.begin(location, "button")
        ledger.callback(location.code, location.permissions.toTypedArray(), intArrayOf(-1, -1))
        assertEquals(listOf(-1, -1), ledger.snapshot().history.last().results)
        assertEquals(2, ledger.snapshot().callbacks)
    }

    @Test fun backCancellationKeepsTheRealEmptyCallbackRatherThanInventingDeniedPermissions() {
        val ledger = PermissionRequestLedger()
        ledger.begin(camera, "button")
        ledger.callback(camera.code, emptyArray(), intArrayOf())
        val event = ledger.snapshot().history.single()
        assertTrue(event.matchedRequest)
        assertTrue(event.cancelled)
        assertFalse(event.permissionsMatch)
        assertTrue(event.permissions.isEmpty())
        assertTrue(event.results.isEmpty())
        assertNull(ledger.snapshot().pending)
    }

    @Test fun unknownCallbackIsVisibleAndDoesNotCompleteThePendingDifferentRequest() {
        val ledger = PermissionRequestLedger()
        val request = ledger.begin(camera, "button")!!
        ledger.callback(location.code, location.permissions.toTypedArray(), intArrayOf(0, 0))
        assertEquals(1, ledger.snapshot().unexpectedCallbacks)
        assertEquals(request, ledger.snapshot().pending)
        assertFalse(ledger.snapshot().history.single().matchedRequest)
        assertEquals(0, ledger.snapshot().history.single().requestSerial)
    }

    @Test fun duplicateCallbacksAreNeverHiddenAsASecondSuccessfulRequest() {
        val ledger = PermissionRequestLedger()
        ledger.begin(camera, "button")
        repeat(2) { ledger.callback(camera.code, camera.permissions.toTypedArray(), intArrayOf(0)) }
        assertEquals(2, ledger.snapshot().callbacks)
        assertEquals(1, ledger.snapshot().unexpectedCallbacks)
        assertFalse(ledger.snapshot().history.last().matchedRequest)
    }

    @Test fun platformArrayMismatchAndMalformedLengthsAreRecordedExactly() {
        val ledger = PermissionRequestLedger()
        ledger.begin(camera, "button")
        val permissions = arrayOf("unexpected.permission")
        val results = intArrayOf(-1, 0)
        ledger.callback(camera.code, permissions, results)
        permissions[0] = "mutated"
        results[0] = 0
        assertEquals(listOf("unexpected.permission"), ledger.snapshot().history.single().permissions)
        assertEquals(listOf(-1, 0), ledger.snapshot().history.single().results)
        assertFalse(ledger.snapshot().history.single().permissionsMatch)
    }

    @Test fun errorsAreNotFabricatedCallbacksAndCannotAbortANewerPendingRequest() {
        val ledger = PermissionRequestLedger()
        val first = ledger.begin(camera, "button")!!
        ledger.failed(first, "java.lang.SecurityException")
        assertEquals(0, ledger.snapshot().callbacks)
        assertNull(ledger.snapshot().pending)
        assertEquals("java.lang.SecurityException", ledger.snapshot().requestError)
        val second = ledger.begin(location, "keyboard")!!
        ledger.failed(first, "stale")
        assertEquals(second, ledger.snapshot().pending)
        assertNull(ledger.snapshot().requestError)
    }

    @Test fun callbackHistoryIsBoundedWithoutLosingTotalCounts() {
        val ledger = PermissionRequestLedger()
        repeat(100) {
            ledger.begin(camera, "button")
            ledger.callback(camera.code, camera.permissions.toTypedArray(), intArrayOf(-1))
        }
        assertEquals(100, ledger.snapshot().requests)
        assertEquals(100, ledger.snapshot().callbacks)
        assertEquals(32, ledger.snapshot().history.size)
        assertEquals(68, ledger.snapshot().droppedCallbacks)
        assertEquals(69, ledger.snapshot().history.first().requestSerial)
        assertEquals(100, ledger.snapshot().history.last().requestSerial)
        assertEquals(0, ledger.snapshot().unexpectedCallbacks)
    }

    @Test fun onlyActualUiActionsCanStartAnObservation() {
        val ledger = PermissionRequestLedger()
        assertThrows(IllegalArgumentException::class.java) { ledger.begin(camera, "intent") }
        assertEquals(0, ledger.snapshot().requests)
    }
}
