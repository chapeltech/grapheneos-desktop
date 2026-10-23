package org.wonad.fixture

/** Bounded observations of real Activity.requestPermissions callbacks, never a permission stub. */
internal class PermissionRequestLedger {
    enum class Kind(val code: Int, val permissions: List<String>) {
        CAMERA(6101, listOf("android.permission.CAMERA")),
        LOCATION(6102, listOf("android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION")),
    }

    data class Request(val serial: Int, val kind: Kind, val action: String) {
        val code: Int get() = kind.code
        val permissions: List<String> get() = kind.permissions
    }
    data class Callback(val serial: Int, val requestSerial: Int, val code: Int,
        val permissions: List<String>, val results: List<Int>, val matchedRequest: Boolean,
        val permissionsMatch: Boolean, val cancelled: Boolean)
    data class Snapshot(val requests: Int, val callbacks: Int, val unexpectedCallbacks: Int,
        val droppedCallbacks: Int, val pending: Request?, val lastRequest: Request?,
        val history: List<Callback>, val requestError: String?)

    private var requestCount = 0
    private var callbackCount = 0
    private var unexpectedCount = 0
    private var droppedCount = 0
    private var pendingRequest: Request? = null
    private var lastRequest: Request? = null
    private var requestError: String? = null
    private val history = ArrayDeque<Callback>()

    @Synchronized fun begin(kind: Kind, action: String): Request? {
        require(action == "button" || action == "keyboard")
        if (pendingRequest != null) return null
        val request = Request(++requestCount, kind, action)
        pendingRequest = request
        lastRequest = request
        requestError = null
        return request
    }

    @Synchronized fun callback(code: Int, permissions: Array<out String>, results: IntArray) {
        val request = pendingRequest
        val matched = request != null && request.code == code
        val actualPermissions = permissions.toList()
        val actualResults = results.toList()
        val event = Callback(++callbackCount, if (matched) request!!.serial else 0, code,
            actualPermissions, actualResults, matched,
            matched && actualPermissions == request!!.permissions
                && actualResults.size == actualPermissions.size,
            actualPermissions.isEmpty() && actualResults.isEmpty())
        if (matched) pendingRequest = null else unexpectedCount++
        if (history.size == MAX_CALLBACKS) {
            history.removeFirst()
            droppedCount++
        }
        history.addLast(event)
    }

    @Synchronized fun failed(request: Request, exception: String) {
        if (pendingRequest == request) {
            pendingRequest = null
            requestError = exception.take(128)
        }
    }

    @Synchronized fun snapshot() = Snapshot(requestCount, callbackCount, unexpectedCount,
        droppedCount, pendingRequest, lastRequest, history.toList(), requestError)

    companion object { const val MAX_CALLBACKS = 32 }
}
