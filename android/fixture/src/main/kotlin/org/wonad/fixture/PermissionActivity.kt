package org.wonad.fixture

import android.content.res.Configuration
import android.graphics.Rect
import android.os.Bundle
import android.os.Process
import android.util.Log
import android.view.KeyEvent
import android.widget.Button
import android.widget.FrameLayout
import android.widget.LinearLayout
import android.widget.TextView
import java.io.FileDescriptor
import java.io.PrintWriter
import java.util.UUID
import org.json.JSONArray
import org.json.JSONObject

/** Requests genuine dangerous permissions only after an ordinary app button/key action. */
class PermissionActivity : FixtureActivity() {
    private val instance = UUID.randomUUID().toString()
    private val ledger = PermissionRequestLedger()
    private val buttons = mutableListOf<Button>()
    private var keyRequests = 0
    private var buttonRequests = 0
    private var lastKey = 0
    @Volatile private var permissionObservation = "{}"

    override fun color(): Int = 0xffead8b7.toInt()

    override fun onCreate(savedState: Bundle?) {
        super.onCreate(savedState)
        val content = findViewById<FrameLayout>(android.R.id.content).getChildAt(0) as LinearLayout
        content.addView(TextView(this).apply {
            text = "Real Android runtime permissions: press C for CAMERA or L for LOCATION.\n" +
                "Respond to Android's trusted permission prompt on the phone."
        })
        for (kind in PermissionRequestLedger.Kind.entries) {
            content.addView(Button(this).apply {
                text = if (kind == PermissionRequestLedger.Kind.CAMERA)
                    "Request CAMERA permission" else "Request LOCATION permissions"
                contentDescription = text
                setOnClickListener { request(kind, "button") }
                buttons += this
            })
        }
        content.addOnLayoutChangeListener { _, _, _, _, _, _, _, _, _ -> publish("layout") }
        publish("created")
    }

    private fun request(kind: PermissionRequestLedger.Kind, action: String) {
        val request = ledger.begin(kind, action) ?: return
        if (action == "keyboard") keyRequests++ else buttonRequests++
        buttons.forEach { it.isEnabled = false }
        publish("request", log = true)
        try {
            // No Intent, options, fabricated callback, pre-grant, or privileged permission API.
            requestPermissions(request.permissions.toTypedArray(), request.code)
        } catch (failure: RuntimeException) {
            ledger.failed(request, failure.javaClass.name)
            buttons.forEach { it.isEnabled = true }
            publish("request_error", log = true)
        }
    }

    override fun dispatchKeyEvent(event: KeyEvent): Boolean {
        val kind = when (event.keyCode) {
            KeyEvent.KEYCODE_C -> PermissionRequestLedger.Kind.CAMERA
            KeyEvent.KEYCODE_L -> PermissionRequestLedger.Kind.LOCATION
            else -> null
        }
        if (kind != null && !event.isCtrlPressed && !event.isAltPressed && !event.isMetaPressed) {
            if (event.action == KeyEvent.ACTION_DOWN && event.repeatCount == 0) {
                lastKey = event.keyCode
                request(kind, "keyboard")
            }
            return true
        }
        return super.dispatchKeyEvent(event)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>,
        grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        ledger.callback(requestCode, permissions, grantResults)
        buttons.forEach { it.isEnabled = ledger.snapshot().pending == null }
        publish("callback", log = true)
    }

    override fun onResume() { super.onResume(); publish("resumed") }
    override fun onPause() { publish("paused"); super.onPause() }
    override fun onConfigurationChanged(newConfig: Configuration) {
        super.onConfigurationChanged(newConfig)
        publish("configuration")
    }
    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        publish(if (hasFocus) "focused" else "unfocused")
    }

    private fun requestJson(request: PermissionRequestLedger.Request?) =
        request?.let { JSONObject().put("serial", it.serial).put("code", it.code)
            .put("kind", it.kind.name).put("action", it.action)
            .put("permissions", JSONArray(it.permissions)) } ?: JSONObject.NULL

    private fun callbackJson(callback: PermissionRequestLedger.Callback) = JSONObject()
        .put("serial", callback.serial).put("request_serial", callback.requestSerial)
        .put("code", callback.code).put("permissions", JSONArray(callback.permissions))
        .put("results", JSONArray(callback.results)).put("matched_request", callback.matchedRequest)
        .put("permissions_match", callback.permissionsMatch).put("cancelled", callback.cancelled)

    private fun publish(event: String, log: Boolean = false) {
        val state = ledger.snapshot()
        val bounds: Rect = windowManager.currentWindowMetrics.bounds
        val actualPermissions = JSONObject()
        PermissionRequestLedger.Kind.entries.flatMap { it.permissions }.forEach {
            actualPermissions.put(it, checkSelfPermission(it))
        }
        permissionObservation = JSONObject().put("schema", 1).put("event", event)
            .put("component", componentName.flattenToShortString())
            .put("run", intent.getStringExtra("wonad_run") ?: JSONObject.NULL)
            .put("instance", instance).put("uid", Process.myUid())
            .put("task", taskId).put("display", display!!.displayId)
            .put("bounds", JSONArray(listOf(bounds.left, bounds.top, bounds.right, bounds.bottom)))
            .put("focused", hasWindowFocus()).put("requests", state.requests)
            .put("callbacks", state.callbacks).put("unexpected_callbacks", state.unexpectedCallbacks)
            .put("dropped_callbacks", state.droppedCallbacks)
            .put("pending", state.pending?.code ?: 0)
            .put("pending_request_serial", state.pending?.serial ?: 0)
            .put("last_request", requestJson(state.lastRequest))
            .put("last_callback", state.history.lastOrNull()?.let(::callbackJson) ?: JSONObject.NULL)
            .put("callback_history", JSONArray(state.history.map(::callbackJson)))
            .put("request_error", state.requestError ?: JSONObject.NULL)
            .put("permission_state", actualPermissions).put("key_requests", keyRequests)
            .put("button_requests", buttonRequests).put("last_key", lastKey).toString()
        if (log) Log.i("WonadFixturePermission", "WONAD_PERMISSION $permissionObservation")
    }

    override fun dump(prefix: String, fd: FileDescriptor?, writer: PrintWriter, args: Array<out String>?) {
        super.dump(prefix, fd, writer, args)
        publish("snapshot")
        writer.println(prefix + "WONAD_PERMISSION " + permissionObservation)
    }
}
